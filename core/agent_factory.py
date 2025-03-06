"""
samsara_ai/agents/core/agent_factory.py

Dynamic Agent Factory with type registry, dependency injection, and instance pooling.
"""

import importlib
import inspect
from typing import Type, Dict, Any, Optional, Generic, TypeVar
from pydantic import BaseModel, ValidationError
import logging
import weakref
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import threading
import redis.asyncio as redis
from prometheus_client import Gauge, Counter

# Type variables
TConfig = TypeVar('TConfig', bound=BaseModel)
TAgent = TypeVar('TAgent', bound='BaseAgent')

# Metrics
FACTORY_INSTANCES_GAUGE = Gauge('agent_factory_instances', 'Active agent instances', ['agent_type'])
FACTORY_ERRORS_COUNTER = Counter('agent_factory_errors', 'Factory errors by type', ['error_code'])

class AgentFactoryError(Exception):
    """Base exception for factory operations"""
    def __init__(self, code: str, context: Dict[str, Any]):
        self.code = code  # Error code like "TYPE_NOT_REGISTERED"
        self.context = context
        super().__init__(f"AgentFactoryError[{code}]")

class AgentFactory(Generic[TConfig, TAgent]):
    """
    Thread-safe factory for agent creation with:
    - Dynamic type registration
    - Instance pooling
    - Dependency injection
    - Async-safe initialization
    """
    
    _registry: Dict[str, Type[TAgent]] = {}
    _instance_pool: weakref.WeakValueDictionary[str, TAgent] = weakref.WeakValueDictionary()
    _lock = threading.RLock()
    _executor = ThreadPoolExecutor(max_workers=4)
    
    def __init__(self, redis_pool: redis.Redis, config_overrides: Optional[Dict[str, Any]] = None):
        self.redis = redis_pool
        self.config_overrides = config_overrides or {}
        self.logger = logging.getLogger("agent.factory")

    @classmethod
    def register(cls, agent_type: str) -> callable:
        """Decorator for registering agent classes"""
        def decorator(agent_cls: Type[TAgent]) -> Type[TAgent]:
            with cls._lock:
                if agent_type in cls._registry:
                    raise AgentFactoryError("TYPE_CONFLICT", {"existing": cls._registry[agent_type]})
                cls._registry[agent_type] = agent_cls
                cls._validate_agent_class(agent_cls)
            return agent_cls
        return decorator

    @classmethod
    def _validate_agent_class(cls, agent_cls: Type[TAgent]) -> None:
        """Ensure agent class implements required interfaces"""
        required_methods = ['process_message', 'start', 'shutdown']
        for method in required_methods:
            if not hasattr(agent_cls, method) or not inspect.iscoroutinefunction(getattr(agent_cls, method)):
                raise AgentFactoryError("INVALID_AGENT", {
                    "class": agent_cls.__name__,
                    "missing": method
                })

    @lru_cache(maxsize=128)
    def _get_config_cls(self, agent_type: str) -> Type[TConfig]:
        """Extract config class from agent type"""
        agent_cls = self._registry.get(agent_type)
        if not agent_cls:
            raise AgentFactoryError("TYPE_NOT_REGISTERED", {"requested": agent_type})
        
        type_hints = inspect.get_annotations(agent_cls.__init__)
        config_cls = type_hints.get('config')
        if not config_cls or not issubclass(config_cls, BaseModel):
            raise AgentFactoryError("INVALID_CONFIG", {"class": agent_cls.__name__})
        
        return config_cls

    async def create(
        self,
        agent_type: str,
        config_data: Dict[str, Any],
        reuse_existing: bool = True
    ) -> TAgent:
        """Create or reuse agent instance with validated config"""
        with self._lock:
            try:
                # Check instance pool first
                instance_id = self._generate_instance_id(agent_type, config_data)
                if reuse_existing and instance_id in self._instance_pool:
                    return self._instance_pool[instance_id]

                # Load agent class
                agent_cls = self._registry[agent_type]
                config_cls = self._get_config_cls(agent_type)
                
                # Merge config with overrides
                merged_config = {**config_data, **self.config_overrides}
                config = config_cls(**merged_config)

                # Dependency injection
                dependencies = {
                    'redis_pool': self.redis,
                    'config': config
                }

                # Async initialization
                agent = agent_cls(**dependencies)
                await agent.start()

                # Track instance
                self._instance_pool[instance_id] = agent
                FACTORY_INSTANCES_GAUGE.labels(agent_type=agent_type).inc()
                
                return agent

            except ValidationError as e:
                self.logger.error(f"Config validation failed: {e}")
                FACTORY_ERRORS_COUNTER.labels(error_code="CONFIG_INVALID").inc()
                raise AgentFactoryError("CONFIG_INVALID", {"errors": e.errors()})
            except Exception as e:
                self.logger.critical(f"Agent creation failed: {str(e)}", exc_info=True)
                FACTORY_ERRORS_COUNTER.labels(error_code="CREATION_FAILED").inc()
                raise AgentFactoryError("CREATION_FAILED", {"exception": str(e)})

    def _generate_instance_id(self, agent_type: str, config: Dict[str, Any]) -> str:
        """Generate unique ID for instance pooling"""
        config_hash = hash(frozenset(config.items()))
        return f"{agent_type}::{config_hash}"

    async def shutdown_all(self) -> None:
        """Gracefully terminate all managed instances"""
        with self._lock:
            for instance_id, agent in list(self._instance_pool.items()):
                try:
                    await agent.shutdown()
                    del self._instance_pool[instance_id]
                except Exception as e:
                    self.logger.error(f"Failed to shutdown {instance_id}: {str(e)}")

    @classmethod
    def load_from_module(cls, module_path: str) -> None:
        """Dynamically register agents from Python modules"""
        try:
            module = importlib.import_module(module_path)
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BaseAgent) and obj != BaseAgent:
                    agent_type = getattr(obj, '__agent_type__', name.lower())
                    cls.register(agent_type)(obj)
        except ImportError as e:
            raise AgentFactoryError("MODULE_LOAD_FAILED", {"path": module_path, "error": str(e)})

    def preload(self, agent_type: str, configs: List[Dict[str, Any]]) -> None:
        """Preload agent instances in background"""
        for config in configs:
            self._executor.submit(
                self.create,
                agent_type=agent_type,
                config_data=config,
                reuse_existing=False
            )

# Example usage
if __name__ == "__main__":
    # Registration via decorator
    @AgentFactory.register("financial_analyzer")
    class FinancialAnalyzer(BaseAgent):
        ...

    # Or dynamic loading
    AgentFactory.load_from_module("samsara_ai.agents.financial")
