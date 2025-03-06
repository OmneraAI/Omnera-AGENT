"""
samsara_ai/security/differential_privacy.py

Enterprise Differential Privacy Module with Budget Accounting and Cross-Framework Support
"""

import numpy as np
import warnings
from typing import Union, Dict, Optional, Tuple
from pydantic import BaseModel, Field, validator
from enum import Enum
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256
from prometheus_client import Gauge, Counter, Histogram
from tenacity import retry, stop_after_attempt, wait_exponential

# Metrics
DP_BUDGET_USAGE = Gauge('dp_budget_used', 'Privacy budget consumption', ['mechanism', 'dataset'])
DP_NOISE_MAGNITUDE = Histogram('dp_noise_magnitude', 'Noise magnitude distribution', ['mechanism'])
DP_VIOLATION_COUNTER = Counter('dp_potential_violations', 'Potential privacy violations detected')

class DPMechanism(str, Enum):
    GAUSSIAN = "gaussian"
    LAPLACE = "laplace"
    EXPONENTIAL = "exponential"
    STAIRCASTEP = "staircase"

class PrivacyBudget(BaseModel):
    total_epsilon: float = Field(..., gt=0)
    total_delta: float = Field(0, ge=0)
    consumed_epsilon: float = 0
    consumed_delta: float = 0
    max_epsilon: Optional[float] = None
    max_delta: Optional[float] = None

    @validator('total_delta')
    def validate_delta(cls, v, values):
        if 'total_epsilon' in values and v >= values['total_epsilon']:
            raise ValueError("Delta must be smaller than epsilon for meaningful privacy")
        return v

class DPConfig(BaseModel):
    mechanism: DPMechanism = DPMechanism.GAUSSIAN
    sensitivity: float = Field(..., gt=0)
    epsilon: float = Field(..., gt=0)
    delta: float = 0
    max_queries: int = 1000
    accountant_type: str = "advanced"
    secure_rng: bool = True
    framework_compat: list = ["numpy", "tensorflow", "pytorch"]

class DifferentialPrivacyEngine:
    def __init__(self, config: DPConfig):
        self.config = config
        self.budget = PrivacyBudget(
            total_epsilon=config.epsilon,
            total_delta=config.delta
        )
        self._init_noise_generator()
        self._validate_security()

    def _init_noise_generator(self):
        """Initialize RNG with cryptographic security"""
        if self.config.secure_rng:
            self.rng = np.random.default_rng()
            # Seed with OS randomness
            with open('/dev/urandom', 'rb') as f:
                seed = int.from_bytes(f.read(8), 'big')
                self.rng = np.random.default_rng(seed)
        else:
            self.rng = np.random.default_rng()

    def _validate_security(self):
        """Check for common DP misconfigurations"""
        if self.config.delta == 0 and self.config.mechanism == DPMechanism.GAUSSIAN:
            warnings.warn("Gaussian mechanism typically requires delta > 0", UserWarning)
        if self.config.epsilon > 10:
            DP_VIOLATION_COUNTER.inc()
            raise ValueError("Epsilon >10 risks insufficient privacy protection")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1))
    def add_noise(self, data: Union[np.ndarray, float], dataset_id: str = "default") -> np.ndarray:
        """
        Apply differentially private noise with budget accounting
        
        Args:
            data: Input data tensor or scalar
            dataset_id: Identifier for privacy budget tracking
            
        Returns:
            Noised data with same shape as input
        """
        self._check_budget(dataset_id)
        
        noise = self._generate_noise(np.shape(data))
        result = data + noise
        
        self._update_budget(dataset_id)
        self._record_metrics(noise, dataset_id)
        
        return result

    def _generate_noise(self, shape: Tuple) -> np.ndarray:
        """Generate noise based on selected mechanism"""
        if self.config.mechanism == DPMechanism.LAPLACE:
            scale = self.config.sensitivity / self.config.epsilon
            return self.rng.laplace(0, scale, shape)
        elif self.config.mechanism == DPMechanism.GAUSSIAN:
            sigma = np.sqrt(2 * np.log(1.25/self.config.delta)) * self.config.sensitivity / self.config.epsilon
            return self.rng.normal(0, sigma, shape)
        elif self.config.mechanism == DPMechanism.STAIRCASTEP:
            return self._staircase_noise(shape)
        else:
            raise NotImplementedError(f"Mechanism {self.config.mechanism} not implemented")

    def _staircase_noise(self, shape: Tuple) -> np.ndarray:
        """Staircase mechanism for discrete-valued data"""
        gamma = np.exp(-self.config.epsilon)
        p = (1 - gamma) / (1 + gamma)
        base = self.rng.choice([-1, 1], size=shape, p=[p, 1-p])
        return base * self.config.sensitivity * self.rng.random(shape)

    def _check_budget(self, dataset_id: str):
        """Validate remaining privacy budget"""
        remaining_epsilon = self.budget.total_epsilon - self.budget.consumed_epsilon
        if remaining_epsilon < (self.config.epsilon / self.config.max_queries):
            DP_VIOLATION_COUNTER.inc()
            raise RuntimeError(f"Privacy budget exhausted for {dataset_id}")
            
        if self.budget.consumed_epsilon + (self.config.epsilon / self.config.max_queries) > self.budget.total_epsilon:
            warnings.warn(f"Approaching budget limit for {dataset_id}", UserWarning)

    def _update_budget(self, dataset_id: str):
        """Update budget using advanced composition theorem"""
        if self.config.accountant_type == "advanced":
            delta_prime = self.config.delta / self.config.max_queries
            self.budget.consumed_delta += delta_prime
            self.budget.consumed_epsilon += (self.config.epsilon * np.sqrt(2 * self.budget.consumed_epsilon * np.log(1/delta_prime)))
        else:
            self.budget.consumed_epsilon += self.config.epsilon
            self.budget.consumed_delta += self.config.delta

    def _record_metrics(self, noise: np.ndarray, dataset_id: str):
        """Record DP metrics for observability"""
        DP_BUDGET_USAGE.labels(self.config.mechanism.value, dataset_id).set(self.budget.consumed_epsilon)
        DP_NOISE_MAGNITUDE.labels(self.config.mechanism.value).observe(np.mean(np.abs(noise)))

    def vectorized_apply(self, data: np.ndarray, axis: int = 0) -> np.ndarray:
        """Optimized vectorized application of DP"""
        noise_shape = list(data.shape)
        noise_shape[axis] = 1
        scale = self.config.sensitivity / self.config.epsilon
        noise = self.rng.laplace(0, scale, noise_shape)
        return data + noise

    def secure_aggregation_wrapper(self, data: np.ndarray) -> np.ndarray:
        """DP-enhanced secure aggregation"""
        h = hmac.HMAC(b"aggregation-key", SHA256())
        h.update(data.tobytes())
        data += np.frombuffer(h.finalize(), dtype=np.float32)
        return self.add_noise(data)

class DPCompositionException(Exception):
    pass

# Example Usage
if __name__ == "__main__":
    config = DPConfig(
        mechanism=DPMechanism.GAUSSIAN,
        sensitivity=1.0,
        epsilon=0.5,
        delta=1e-5
    )
    
    dp_engine = DifferentialPrivacyEngine(config)
    
    original_data = np.random.randn(100, 50)
    protected_data = dp_engine.add_noise(original_data, "test_dataset")
    
    print(f"Noise magnitude: {np.linalg.norm(protected_data - original_data):.2f}")
    print(f"Consumed budget: ε={dp_engine.budget.consumed_epsilon:.4f}, δ={dp_engine.budget.consumed_delta:.2e}")
