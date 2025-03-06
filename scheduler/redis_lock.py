"""
samsara_ai/infrastructure/locking/redis_lock.py

Enterprise Redis Distributed Lock with Deadlock Prevention and Metrics
"""

import redis
import time
import uuid
import logging
from typing import Optional, Dict, Tuple
from prometheus_client import Gauge, Counter, Histogram
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from cryptography.fernet import Fernet
import json

# Prometheus Metrics
LOCK_ACQUIRE_TIME = Histogram('redis_lock_acquire_seconds', 'Lock acquisition latency', ['lock_name'])
LOCK_HOLD_TIME = Histogram('redis_lock_hold_seconds', 'Lock hold duration', ['lock_name'])
LOCK_WAITERS_GAUGE = Gauge('redis_lock_waiters_total', 'Current waiters per lock', ['lock_name'])
LOCK_RETRY_COUNTER = Counter('redis_lock_retries_total', 'Lock acquisition retries', ['lock_name', 'reason'])

class RedisLockException(Exception):
    pass

class LockTimeout(RedisLockException):
    pass

class DeadlockDetected(RedisLockException):
    pass

class RedisLock:
    def __init__(
        self,
        redis_client: redis.Redis,
        lock_name: str,
        timeout: int = 30,
        auto_renew: bool = True,
        wait_timeout: int = 60,
        lock_prefix: str = "samsara:lock:"
    ):
        self.redis = redis_client
        self.lock_name = f"{lock_prefix}{lock_name}"
        self.timeout = timeout
        self.auto_renew = auto_renew
        self.wait_timeout = wait_timeout
        self.identifier = self._generate_identifier()
        self._lock_renewal_thread = None
        self.logger = logging.getLogger("redis_lock")
        
        # Encryption for audit logs
        self.cipher = Fernet(os.getenv("LOCK_FERNET_KEY").encode())

    def _generate_identifier(self) -> str:
        return f"{uuid.uuid4().hex}_{os.getenv('POD_ID', 'local')}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, max=10),
        retry=retry_if_exception_type(redis.exceptions.ConnectionError)
    )
    def acquire(self, blocking: bool = True) -> bool:
        """
        Acquire lock with deadlock detection and hierarchical locking
        """
        start_time = time.monotonic()
        attempt = 0
        
        while True:
            # Deadlock prevention checks
            if self._detect_deadlock():
                LOCK_RETRY_COUNTER.labels(self.lock_name, "deadlock").inc()
                raise DeadlockDetected(f"Deadlock detected for {self.lock_name}")
                
            # Hierarchical locking protocol
            parent_lock = self._get_parent_lock()
            if parent_lock and not parent_lock.is_held():
                LOCK_RETRY_COUNTER.labels(self.lock_name, "parent_unlocked").inc()
                raise RedisLockException("Parent lock not held")
                
            acquired = self._acquire_single(blocking)
            
            if acquired or not blocking:
                break
                
            if time.monotonic() - start_time > self.wait_timeout:
                raise LockTimeout(f"Timeout waiting for {self.lock_name}")
                
            attempt += 1
            time.sleep(0.1 * min(attempt, 10))
            
        if acquired:
            latency = time.monotonic() - start_time
            LOCK_ACQUIRE_TIME.labels(self.lock_name).observe(latency)
            LOCK_WAITERS_GAUGE.labels(self.lock_name).dec()
            self._start_auto_renew()
            self._write_audit_log("acquire")
            
        return acquired

    def _acquire_single(self, blocking: bool) -> bool:
        """
        Single lock acquisition attempt using Redis SET with NX and PX
        """
        try:
            acquired = self.redis.set(
                self.lock_name,
                self.identifier,
                nx=True,
                px=self.timeout * 1000
            )
            if not acquired and blocking:
                self._register_waiter()
            return acquired is not None
        except redis.RedisError as e:
            self.logger.error(f"Lock acquisition failed: {str(e)}")
            raise

    def _detect_deadlock(self) -> bool:
        """
        Detect circular wait conditions using lock dependency graph
        """
        dependencies = self.redis.get(f"{self.lock_name}:deps")
        if not dependencies:
            return False
            
        dep_graph = json.loads(dependencies)
        return self._check_cycle(dep_graph)

    def _check_cycle(self, graph: Dict) -> bool:
        """
        Graph cycle detection using DFS
        """
        visited = set()
        stack = set()
        
        def dfs(node):
            if node in stack:
                return True
            if node in visited:
                return False
                
            visited.add(node)
            stack.add(node)
            
            for neighbor in graph.get(node, []):
                if dfs(neighbor):
                    return True
                    
            stack.remove(node)
            return False
            
        return any(dfs(node) for node in graph if node not in visited)

    def _get_parent_lock(self) -> Optional['RedisLock']:
        """
        Get parent lock based on hierarchical naming convention
        e.g., "resource:1" -> "resource:group"
        """
        if ":" not in self.lock_name:
            return None
            
        parent_name = ":".join(self.lock_name.split(":")[:-1])
        return RedisLock(self.redis, parent_name)

    def _register_waiter(self):
        """
        Register current process as waiting for the lock
        """
        self.redis.zadd(
            f"{self.lock_name}:waiters",
            {self.identifier: time.time()}
        )
        LOCK_WAITERS_GAUGE.labels(self.lock_name).inc()

    def _start_auto_renew(self):
        """
        Start background thread for automatic lock renewal
        """
        if self.auto_renew:
            from threading import Thread
            self._lock_renewal_thread = Thread(target=self._renew_loop)
            self._lock_renewal_thread.daemon = True
            self._lock_renewal_thread.start()

    def _renew_loop(self):
        """
        Continuously renew lock until released
        """
        try:
            while True:
                time.sleep(self.timeout * 0.75)
                if not self.renew():
                    break
        except Exception as e:
            self.logger.error(f"Lock renewal failed: {str(e)}")

    def renew(self) -> bool:
        """
        Renew existing lock expiration time
        """
        if not self.is_held():
            return False
            
        try:
            renewed = self.redis.pexpire(
                self.lock_name,
                int(self.timeout * 1000),
                xx=True,
                gt=True
            )
            if renewed:
                self._write_audit_log("renew")
            return renewed
        except redis.RedisError as e:
            self.logger.error(f"Lock renewal error: {str(e)}")
            return False

    def release(self) -> None:
        """
        Release lock with verification and cleanup
        """
        try:
            self._verify_ownership()
            self.redis.delete(self.lock_name)
            self._cleanup_waiters()
            self._write_audit_log("release")
            
            hold_duration = time.monotonic() - self._get_lock_timestamp()
            LOCK_HOLD_TIME.labels(self.lock_name).observe(hold_duration)
        except redis.RedisError as e:
            self.logger.error(f"Lock release failed: {str(e)}")
            raise

    def _verify_ownership(self) -> None:
        """
        Verify current instance owns the lock
        """
        current_id = self.redis.get(self.lock_name)
        if current_id != self.identifier.encode():
            raise RedisLockException("Lock ownership verification failed")

    def _cleanup_waiters(self) -> None:
        """
        Clean up waiter registration and dependencies
        """
        self.redis.zrem(f"{self.lock_name}:waiters", self.identifier)
        self.redis.delete(f"{self.lock_name}:deps")

    def _write_audit_log(self, action: str) -> None:
        """
        Write encrypted audit log entry
        """
        log_entry = json.dumps({
            "timestamp": time.time(),
            "lock": self.lock_name,
            "action": action,
            "identifier": self.identifier,
            "host": os.getenv("HOSTNAME", "unknown")
        }).encode()
        
        encrypted_log = self.cipher.encrypt(log_entry)
        self.redis.rpush("samsara:lock:audit", encrypted_log)

    def _get_lock_timestamp(self) -> float:
        """
        Get lock acquisition timestamp from Redis
        """
        pttl = self.redis.pttl(self.lock_name)
        return (time.time() * 1000 - pttl) / 1000 if pttl > 0 else 0

    def is_held(self) -> bool:
        """
        Check if lock is currently held by this instance
        """
        try:
            stored_id = self.redis.get(self.lock_name)
            return stored_id == self.identifier.encode()
        except redis.RedisError:
            return False

    def __enter__(self):
        self.acquire(blocking=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

# Example Usage
if __name__ == "__main__":
    redis_client = redis.Redis.from_url("redis://localhost:6379/0")
    
    with RedisLock(redis_client, "customer_data:1234", timeout=30) as lock:
        # Critical section
        print("Lock acquired, performing operation...")
        time.sleep(10)
