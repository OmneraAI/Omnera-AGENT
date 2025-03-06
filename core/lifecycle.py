"""
samsara_ai/agents/core/lifecycle.py

Agent lifecycle management with state transitions, persistence, and recovery.
"""

import asyncio
import logging
from enum import Enum, auto
from typing import Dict, Optional, Type, TypeVar
from pydantic import BaseModel, ValidationError
import redis.asyncio as redis
from datetime import datetime, timezone
from prometheus_client import Gauge, Histogram
from dataclasses import dataclass, field
import json
from functools import partial
from uuid import uuid4
from contextlib import asynccontextmanager

# Type variables
T = TypeVar('T', bound='AgentLifecycle')

# Metrics
LIFECYCLE_STATE_GAUGE = Gauge('agent_lifecycle_state', 'Current agent state', ['agent_id', 'state'])
LIFECYCLE_TRANSITION_TIME = Histogram('agent_lifecycle_transition_duration', 'State transition duration', ['from_state', 'to_state'])

class LifecycleState(Enum):
    CREATED = auto()
    INITIALIZING = auto()
    READY = auto()
    RUNNING = auto()
    PAUSED = auto()
    ERROR = auto()
    TERMINATING = auto()
    TERMINATED = auto()

class LifecycleConfig(BaseModel):
    state_ttl: int = 300  # Seconds to persist state in Redis
    recovery_attempts: int = 3
    recovery_backoff: float = 1.5
    heartbeat_interval: int = 30

@dataclass
class AgentLifecycle:
    agent_id: str = field(default_factory=lambda: str(uuid4()))
    state: LifecycleState = LifecycleState.CREATED
    state_history: Dict[datetime, LifecycleState] = field(default_factory=dict)
    _redis: redis.Redis = field(repr=False)
    _config: LifecycleConfig = field(default_factory=LifecycleConfig)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _logger: logging.Logger = field(init=False)
    _heartbeat_task: Optional[asyncio.Task] = None

    def __post_init__(self):
        self._logger = logging.getLogger(f"lifecycle.{self.agent_id[:8]}")
        LIFECYCLE_STATE_GAUGE.labels(agent_id=self.agent_id, state=self.state.name).set(1)

    @classmethod
    async def create(
        cls: Type[T], 
        redis_pool: redis.Redis,
        config: Optional[Dict] = None
    ) -> T:
        """Factory method with async initialization"""
        validated_config = LifecycleConfig(**(config or {}))
        instance = cls(
            _redis=redis_pool,
            _config=validated_config
        )
        await instance._persist_state()
        return instance

    async def transition(
        self, 
        new_state: LifecycleState,
        metadata: Optional[Dict] = None
    ) -> None:
        """Atomic state transition with persistence"""
        async with self._lock:
            start_time = datetime.now(timezone.utc)
            prev_state = self.state

            try:
                # Validate transition
                allowed_transitions = {
                    LifecycleState.CREATED: [LifecycleState.INITIALIZING],
                    LifecycleState.INITIALIZING: [LifecycleState.READY, LifecycleState.ERROR],
                    LifecycleState.READY: [LifecycleState.RUNNING, LifecycleState.TERMINATING],
                    LifecycleState.RUNNING: [LifecycleState.PAUSED, LifecycleState.ERROR, LifecycleState.TERMINATING],
                    LifecycleState.PAUSED: [LifecycleState.RUNNING, LifecycleState.TERMINATING],
                    LifecycleState.ERROR: [LifecycleState.TERMINATING, LifecycleState.READY],
                    LifecycleState.TERMINATING: [LifecycleState.TERMINATED]
                }

                if new_state not in allowed_transitions.get(self.state, []):
                    raise InvalidTransitionError(
                        f"Cannot transition from {self.state.name} to {new_state.name}"
                    )

                # Update state
                self.state = new_state
                self.state_history[datetime.now(timezone.utc)] = new_state
                
                # Update metrics
                LIFECYCLE_STATE_GAUGE.labels(
                    agent_id=self.agent_id, 
                    state=self.state.name
                ).set(1)
                LIFECYCLE_TRANSITION_TIME.labels(
                    from_state=prev_state.name,
                    to_state=new_state.name
                ).observe((datetime.now(timezone.utc) - start_time).total_seconds())

                # State-specific actions
                if new_state == LifecycleState.RUNNING:
                    self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                elif new_state == LifecycleState.TERMINATED:
                    if self._heartbeat_task and not self._heartbeat_task.done():
                        self._heartbeat_task.cancel()

                # Persist state
                await self._persist_state(metadata)
                
                self._logger.info(
                    f"Transitioned from {prev_state.name} to {new_state.name}",
                    extra={"metadata": metadata}
                )

            except Exception as e:
                self._logger.error(
                    f"Failed transition to {new_state.name}: {str(e)}",
                    exc_info=True
                )
                await self.transition(LifecycleState.ERROR, {"error": str(e)})
                raise

    async def _persist_state(self, metadata: Optional[Dict] = None) -> None:
        """Persist state to Redis with TTL"""
        state_data = {
            "state": self.state.name,
            "history": {
                iso: state.name 
                for iso, state in self.state_history.items()
            },
            "metadata": metadata or {}
        }
        await self._redis.setex(
            f"samsara:lifecycle:{self.agent_id}",
            self._config.state_ttl,
            json.dumps(state_data)
        )

    async def recover(self) -> None:
        """State recovery with retry logic"""
        for attempt in range(self._config.recovery_attempts):
            try:
                raw_data = await self._redis.get(f"samsara:lifecycle:{self.agent_id}")
                if not raw_data:
                    raise StateNotFoundError("No persisted state found")
                
                state_data = json.loads(raw_data)
                recovered_state = LifecycleState[state_data["state"]]
                
                await self.transition(recovered_state, state_data["metadata"])
                return
                
            except (StateNotFoundError, json.JSONDecodeError, KeyError) as e:
                if attempt == self._config.recovery_attempts - 1:
                    await self.transition(
                        LifecycleState.ERROR,
                        {"recovery_error": str(e)}
                    )
                    raise RecoveryFailedError(
                        f"Recovery failed after {self._config.recovery_attempts} attempts"
                    ) from e
                
                backoff = self._config.recovery_backoff ** (attempt + 1)
                await asyncio.sleep(backoff)

    async def _heartbeat_loop(self) -> None:
        """Periodic state persistence for health checks"""
        while self.state in {LifecycleState.RUNNING, LifecycleState.PAUSED}:
            try:
                await self._persist_state()
                await asyncio.sleep(self._config.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.error(f"Heartbeat failed: {str(e)}")
                await self.transition(LifecycleState.ERROR, {"heartbeat_failure": str(e)})
                break

    @asynccontextmanager
    async def managed_run(self):
        """Context manager for safe execution"""
        try:
            await self.transition(LifecycleState.INITIALIZING)
            await self.transition(LifecycleState.READY)
            await self.transition(LifecycleState.RUNNING)
            yield
        except Exception as e:
            await self.transition(LifecycleState.ERROR, {"runtime_error": str(e)})
            raise
        finally:
            if self.state != LifecycleState.TERMINATED:
                await self.transition(LifecycleState.TERMINATING)
                await self.transition(LifecycleState.TERMINATED)

class InvalidTransitionError(RuntimeError):
    """Invalid state transition attempt"""

class StateNotFoundError(ValueError):
    """Persisted state not found in storage"""

class RecoveryFailedError(RuntimeError):
    """State recovery failed after multiple attempts"""

# Example usage
async def main():
    redis_pool = redis.Redis.from_url("redis://localhost:6379")
    
    async with AgentLifecycle.create(redis_pool) as lifecycle:
        async with lifecycle.managed_run():
            # Agent operational logic here
            await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(main())
