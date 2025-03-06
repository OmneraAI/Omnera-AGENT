"""
samsara_ai/aggregation/core/aggregator.py

Enterprise-grade Aggregator with Differential Privacy, Model Fusion, and Multi-Tenancy Support
"""

import asyncio
import numpy as np
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel, ValidationError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from prometheus_client import Histogram, Counter, Gauge
from tenacity import retry, stop_after_attempt, wait_exponential
from .proto.aggregation_pb2 import AggregationPayload, AggregationMetadata

# Prometheus Metrics
AGGREGATION_TIME = Histogram('aggregator_process_seconds', 'Aggregation latency by strategy', ['strategy'])
FUSION_ERRORS = Counter('aggregator_fusion_errors_total', 'Model fusion failures by type', ['error_type'])
DATA_VOLUME = Gauge('aggregator_input_bytes', 'Input data volume per aggregation cycle')
FEDERATED_ROUNDS = Counter('aggregator_federated_rounds_total', 'Completed federated learning rounds')

class AggregationConfig(BaseModel):
    strategy: str = 'fedavg'
    differential_epsilon: float = 3.0
    max_workers: int = 8
    timeout_sec: int = 300
    model_encryption_key: Optional[str] = None
    data_validation: bool = True

class SecureAggregator:
    def __init__(self, redis_client, config: AggregationConfig):
        self.redis = redis_client
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_workers)
        self._init_crypto()

    def _init_crypto(self):
        """Initialize cryptographic components based on config"""
        if self.config.model_encryption_key:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            self.encryption_key = kdf.derive(self.config.model_encryption_key.encode())
        else:
            self.encryption_key = None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def federated_aggregate(self, participant_updates: List[Dict]) -> Dict:
        """
        Federated aggregation pipeline with privacy guarantees
        """
        FEDERATED_ROUNDS.inc()
        
        try:
            # Phase 1: Secure data collection
            validated_data = await self._parallel_validate(participant_updates)
            
            # Phase 2: Strategy-specific aggregation
            with AGGREGATION_TIME.labels(self.config.strategy).time():
                if self.config.strategy == 'fedavg':
                    result = self._fedavg(validated_data)
                elif self.config.strategy == 'fedsgd':
                    result = self._fedsgd(validated_data)
                else:
                    raise ValueError(f"Unsupported strategy: {self.config.strategy}")

            # Phase 3: Differential privacy enforcement
            if self.config.differential_epsilon < float('inf'):
                result = self._apply_dp(result)

            return self._package_result(result)

        except ValidationError as ve:
            FUSION_ERRORS.labels(error_type='validation').inc()
            raise AggregationError(f"Data validation failed: {str(ve)}")
        except CryptographicError as ce:
            FUSION_ERRORS.labels(error_type='security').inc()
            raise AggregationError(f"Security violation: {str(ce)}")

    async def _parallel_validate(self, updates: List[Dict]) -> List[np.ndarray]:
        """
        Parallel data validation and decryption
        """
        loop = asyncio.get_event_loop()
        futures = [
            loop.run_in_executor(
                self.executor,
                self._process_single_update,
                update
            ) for update in updates
        ]
        return await asyncio.gather(*futures)

    def _process_single_update(self, update: Dict) -> np.ndarray:
        """
        Validate and decrypt individual participant update
        """
        try:
            # Protocol Buffer validation
            payload = AggregationPayload.FromString(update['data'])
            metadata = AggregationPayload.Metadata.FromString(update['metadata'])
            
            # Data integrity check
            if metadata.sha256 != self._compute_hash(payload.model_weights):
                raise ValidationError("Hash mismatch detected")

            # Decrypt if needed
            if payload.encryption_algo != AggregationPayload.ENCRYPTION_NONE:
                decrypted = self._decrypt_weights(payload.model_weights)
                return np.frombuffer(decrypted, dtype=np.float32)
                
            return np.frombuffer(payload.model_weights, dtype=np.float32)

        except Exception as e:
            raise ValidationError(f"Update processing failed: {str(e)}")

    def _fedavg(self, weights_list: List[np.ndarray]) -> np.ndarray:
        """
        Federated Averaging with weighting by sample size
        """
        total_samples = sum(w[0] for w in weights_list)
        weighted_sum = np.zeros_like(weights_list[0][1])
        
        for samples, weights in weights_list:
            weighted_sum += (samples / total_samples) * weights
            
        return weighted_sum

    def _fedsgd(self, gradients_list: List[np.ndarray]) -> np.ndarray:
        """
        Federated SGD with gradient clipping
        """
        clipped_gradients = [np.clip(g, -1.0, 1.0) for g in gradients_list]
        return np.mean(clipped_gradients, axis=0)

    def _apply_dp(self, model_update: np.ndarray) -> np.ndarray:
        """
        Apply differential privacy using Gaussian mechanism
        """
        sensitivity = 1.0  # Configure based on data scaling
        sigma = np.sqrt(2 * np.log(1.25 / 1e-5)) * sensitivity / self.config.differential_epsilon
        noise = np.random.normal(0, sigma, model_update.shape)
        return model_update + noise

    def _package_result(self, result: np.ndarray) -> Dict:
        """
        Prepare aggregation result with security metadata
        """
        if self.encryption_key:
            encrypted = self._encrypt_weights(result.tobytes())
            return {
                'data': encrypted,
                'encryption_algo': 'AES256-GCM',
                'integrity_hash': self._compute_hash(encrypted)
            }
        else:
            return {
                'data': result.tobytes(),
                'integrity_hash': self._compute_hash(result.tobytes())
            }

    def _compute_hash(self, data: bytes) -> str:
        """
        Compute SHA-256 hash of data payload
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize().hex()

    def _encrypt_weights(self, plaintext: bytes) -> bytes:
        """
        AES-GCM encryption for model weights
        """
        if not self.encryption_key:
            raise CryptographicError("Encryption key not configured")
        
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def _decrypt_weights(self, ciphertext: bytes) -> bytes:
        """
        AES-GCM decryption for model weights
        """
        if not self.encryption_key:
            raise CryptographicError("Encryption key not configured")
            
        iv = ciphertext[:12]
        tag = ciphertext[12:28]
        encrypted_data = ciphertext[28:]
        
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

class AggregationError(Exception):
    pass

class CryptographicError(AggregationError):
    pass

# Example Usage
if __name__ == "__main__":
    from redis import Redis
    import numpy as np
    
    config = AggregationConfig(
        strategy='fedavg',
        differential_epsilon=3.0,
        model_encryption_key="secure-passphrase"
    )
    
    aggregator = SecureAggregator(Redis(), config)
    
    # Simulate participant updates
    updates = [{
        'data': np.random.rand(100).astype(np.float32).tobytes(),
        'metadata': b''  # Actual metadata would include hash
    } for _ in range(10)]
    
    result = asyncio.run(aggregator.federated_aggregate(updates))
    print(f"Aggregated model shape: {np.frombuffer(result['data']).shape}")
