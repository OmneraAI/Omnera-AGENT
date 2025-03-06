"""
samsara_ai/agents/core/agent_base.py

Base Agent class with lifecycle management, security, and observability hooks.
"""

from __future__ import annotations
import abc
import logging
import uuid
from typing import Any, Dict, Optional, TypeVar
from pydantic import BaseModel, ValidationError
from cryptography.fernet import Fernet
from prometheus_client import Counter, Histogram
import redis.asyncio as redis
from opentelemetry import trace

# Type variables
TConfig = TypeVar('TConfig', bound=BaseModel)
TMessage = TypeVar('TMessage', bound=BaseModel)

# Metrics
AGENT_START_COUNTER = Counter('agent_start_total', 'Agent startups', ['agent_type'])
TASK_DURATION = Histogram('task_duration_seconds', 'Task latency', ['task_type'])

# Tracing
tracer = trace.get_tracer("samsara.agent")

class AgentException(Exception):
    """Base exception for agent operations"""
    def __init__(self, code: str, context: Dict[str, Any]):
        self.code = code  # Error code like "AUTH_FAILURE"
        self.context = context  # Debugging context
        super().__init__(f"AgentError[{code}]")

class AgentConfiguration(BaseModel):
    """Base configuration schema for all agents"""
    agent_id: str = uuid.uuid4().hex
    heartbeat_interval: int = 30
    max_retries: int = 3
    crypto_key: Optional[str] = None  # Fernet-compatible key

class BaseAgent(abc.ABC):
    """
    Abstract base class for all Samsara AI agents
    
    Features:
    - Lifecycle hooks (init/start/shutdown)
    - Cryptographic message validation
    - Metrics & tracing
    - Retry/backoff policies
    - Configuration validation
    """
    
    def __init__(self, config: TConfig, redis_pool: redis.Redis):
        self._validate_config(config)
        self.config = config
        self.redis = redis_pool
        self.crypto = self._init_crypto()
        self.logger = logging.getLogger(f"agent.{self.__class__.__name__}")
        self._is_running = False

    def _validate_config(self, config: TConfig) -> None:
        """Enforce configuration schema using Pydantic"""
        try:
            self.__annotations__['config'](config)  # Validate via type hint
        except ValidationError as e:
            self.logger.error(f"Config validation failed: {e}")
            raise AgentException("CONFIG_INVALID", {"errors": e.errors()})

    def _init_crypto(self) -> Optional[Fernet]:
        """Initialize cryptography layer if key provided"""
        if self.config.crypto_key:
            if len(self.config.crypto_key) != 44:  # Fernet key length check
                raise AgentException("CRYPTO_INVALID", {"key_length": len(self.config.crypto_key)})
            return Fernet(self.config.crypto_key.encode())
        return None

    @abc.abstractmethod
    async def process_message(self, message: TMessage) -> Dict[str, Any]:
        """Main message processing entrypoint (implement in subclasses)"""
        pass

    async def start(self) -> None:
        """Start agent background tasks"""
        if self._is_running:
            self.logger.warning("Agent already running")
            return
        
        with tracer.start_as_current_span("AgentStartup"):
            AGENT_START_COUNTER.labels(agent_type=self.__class__.__name__).inc()
            
            try:
                await self._connect_dependencies()
                self._is_running = True
                self.logger.info(f"Agent {self.config.agent_id} started")
            except Exception as e:
                self.logger.critical(f"Startup failed: {str(e)}", exc_info=True)
                raise AgentException("STARTUP_FAILED", {"exception": str(e)})

    async def shutdown(self) -> None:
        """Graceful shutdown sequence"""
        self._is_running = False
        self.logger.info(f"Agent {self.config.agent_id} shutting down")

    def _secure_serialize(self, data: Dict[str, Any]) -> str:
        """Encrypt sensitive data before transmission"""
        if not self.crypto:
            return json.dumps(data)
        
        plaintext = json.dumps(data).encode()
        return self.crypto.encrypt(plaintext).decode()

    def _secure_deserialize(self, payload: str) -> Dict[str, Any]:
        """Decrypt and validate incoming messages"""
        if not self.crypto:
            return json.loads(payload)
        
        try:
            decrypted = self.crypto.decrypt(payload.encode())
            return json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError) as e:
            self.logger.error(f"Decryption failed: {type(e).__name__}")
            raise AgentException("MSG_INVALID", {"error": str(e)})

    async def _connect_dependencies(self) -> None:
        """Initialize connections to external services"""
        # Implementation for Redis/DB/etc connections
        pass

    @property
    def status(self) -> Dict[str, Any]:
        """Current agent health status"""
        return {
            "running": self._is_running,
            "agent_id": self.config.agent_id,
            "metrics": {
                "processed": TASK_DURATION._metrics.copy()  # Actual metric values
            }
        }

    def __enter__(self):
        """Context manager support"""
        asyncio.run(self.start())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup on context exit"""
        asyncio.run(self.shutdown())

# Example concrete implementation
class ExampleAgent(BaseAgent):
    """Sample agent implementation"""
    
    class ExampleConfig(AgentConfiguration):
        """Extended configuration"""
        target_url: str
        timeout: int = 10

    class ExampleMessage(BaseModel):
        """Input message schema"""
        task_id: str
        payload: Dict[str, float]

    def __init__(self, config: ExampleConfig, redis_pool: redis.Redis):
        super().__init__(config, redis_pool)
        self.session = aiohttp.ClientSession()

    async def process_message(self, message: ExampleMessage) -> Dict[str, Any]:
        """Sample processing flow"""
        with TASK_DURATION.labels(task_type="http_request").time():
            async with self.session.get(
                self.config.target_url,
                timeout=self.config.timeout,
                params=message.payload
            ) as response:
                return await response.json()
