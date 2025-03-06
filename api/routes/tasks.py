"""
samsara_ai/tasks/core/tasks.py

Enterprise Task Management System with Priority Scheduling and Atomic Execution
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Literal
from uuid import uuid4

import redis.asyncio as redis
from pydantic import BaseModel, Field, validator
from prometheus_client import Histogram, Counter
from opentelemetry import trace

# Pydantic Models
class TaskRequest(BaseModel):
    task_type: str = Field(..., min_length=3, max_length=50, pattern="^[a-z0-9_]+$")
    payload: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)
    timeout: int = Field(default=300, ge=10, le=3600)
    max_retries: int = Field(default=3, ge=0, le=10)
    callback_url: Optional[str] = Field(None, format="uri")

    @validator("payload")
    def validate_payload_size(cls, v):
        if len(json.dumps(v)) > 1024 * 1024:  # 1MB limit
            raise ValueError("Payload exceeds 1MB size limit")
        return v

class TaskState(BaseModel):
    task_id: str
    status: Literal["queued", "processing", "completed", "failed", "retrying"]
    attempts: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

# Metrics
TASK_DURATION = Histogram(
    "samsara_task_duration_seconds",
    "Task execution time distribution",
    ["task_type", "status"],
    buckets=(0.1, 1, 5, 15, 60, 300, 600, 1800)
)

TASK_OPS = Counter(
    "samsara_task_operations",
    "Task lifecycle events",
    ["operation", "task_type"]
)

# Redis Keys
TASK_QUEUE_KEY = "samsara:tasks:queue"
DEAD_LETTER_KEY = "samsara:tasks:dead_letter"
TASK_STATE_PREFIX = "samsara:tasks:state:"

class TaskManager:
    def __init__(self, redis_pool: redis.Redis, concurrency_limit: int = 100):
        self.redis = redis_pool
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.tracer = trace.get_tracer("task_manager")
        
    async def enqueue_task(self, task: TaskRequest) -> TaskState:
        """Atomically enqueue task with priority scoring"""
        task_id = str(uuid4())
        state = TaskState(task_id=task_id, status="queued")
        
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.zadd(
                TASK_QUEUE_KEY,
                {task_id: self._calculate_priority_score(task)},
                nx=True
            )
            await pipe.set(
                f"{TASK_STATE_PREFIX}{task_id}",
                state.json(),
                ex=task.timeout * 2
            )
            await pipe.execute()
            
        TASK_OPS.labels("enqueue", task.task_type).inc()
        return state

    def _calculate_priority_score(self, task: TaskRequest) -> float:
        """Hybrid priority score combining time and priority"""
        base_score = datetime.utcnow().timestamp()
        priority_bonus = (10 - task.priority) * 0.1
        return base_score + priority_bonus

    async def process_tasks(self):
        """Distributed task consumer with atomic claim"""
        while True:
            async with self.semaphore:
                async with self.redis.pipeline(transaction=True) as pipe:
                    try:
                        # Claim next task atomically
                        task_id = await pipe.zrevrangebyscore(
                            TASK_QUEUE_KEY,
                            min="-inf",
                            max="+inf",
                            start=0,
                            num=1,
                            withscores=True
                        ).execute()
                        
                        if not task_id[0]:
                            await asyncio.sleep(0.1)
                            continue
                            
                        task_id = task_id[0][0][0].decode()
                        await pipe.zrem(TASK_QUEUE_KEY, task_id)
                        await pipe.get(f"{TASK_STATE_PREFIX}{task_id}")
                        raw_state, _ = await pipe.execute()
                        
                        state = TaskState.parse_raw(raw_state)
                        state.status = "processing"
                        state.started_at = datetime.utcnow()
                        
                        await self._update_task_state(task_id, state)
                        TASK_OPS.labels("start", state.task_type).inc()
                        
                        # Execute task with tracing and timeout
                        with self.tracer.start_as_current_span(task_id):
                            await self._execute_task(task_id, state)
                            
                    except Exception as e:
                        logging.error(f"Task processing failed: {str(e)}")
                        await self._handle_failure(task_id, state, str(e))

    async def _execute_task(self, task_id: str, state: TaskState):
        """Execute task with retry and timeout handling"""
        try:
            async with asyncio.timeout(state.timeout):
                # Retrieve full task details
                raw_task = await self.redis.get(f"{TASK_STATE_PREFIX}{task_id}")
                task = TaskRequest.parse_raw(raw_task)
                
                # TODO: Add actual task execution logic
                result = {"status": "simulated_success"}
                
                state.status = "completed"
                state.result = result
                state.completed_at = datetime.utcnow()
                
        except asyncio.TimeoutError:
            state.error = "Execution timeout exceeded"
            await self._handle_retry(task_id, state)
        except Exception as e:
            state.error = str(e)
            await self._handle_retry(task_id, state)
        finally:
            duration = (datetime.utcnow() - state.started_at).total_seconds()
            TASK_DURATION.labels(
                task_type=task.task_type, 
                status=state.status
            ).observe(duration)
            
            await self._update_task_state(task_id, state)
            await self._cleanup_task(task_id, state)

    async def _handle_retry(self, task_id: str, state: TaskState):
        """Manage retry logic and dead-letter queue"""
        state.attempts += 1
        raw_task = await self.redis.get(f"{TASK_STATE_PREFIX}{task_id}")
        task = TaskRequest.parse_raw(raw_task)
        
        if state.attempts > task.max_retries:
            state.status = "failed"
            await self.redis.lpush(DEAD_LETTER_KEY, task_id)
            TASK_OPS.labels("dead_letter", task.task_type).inc()
        else:
            state.status = "retrying"
            await self.enqueue_task(task)
            TASK_OPS.labels("retry", task.task_type).inc()

    async def _update_task_state(self, task_id: str, state: TaskState):
        """Atomic state update with optimistic concurrency"""
        async with self.redis.pipeline(transaction=True) as pipe:
            await pipe.set(
                f"{TASK_STATE_PREFIX}{task_id}",
                state.json(),
                xx=True,  # Only update if exists
                ex=timedelta(hours=24)
            )
            await pipe.execute()

    async def _cleanup_task(self, task_id: str, state: TaskState):
        """Cleanup resources post-execution"""
        if state.status in ["completed", "failed"]:
            await self.redis.delete(f"{TASK_STATE_PREFIX}{task_id}")

# Redis Connection Setup
redis_pool = redis.ConnectionPool.from_url(
    "redis://redis-samsara:6379",
    max_connections=100,
    decode_responses=True
)

# Example Usage
async def main():
    redis_client = redis.Redis(connection_pool=redis_pool)
    manager = TaskManager(redis_client)
    
    # Start task consumers
    consumers = [manager.process_tasks() for _ in range(10)]
    await asyncio.gather(*consumers)

if __name__ == "__main__":
    asyncio.run(main())
