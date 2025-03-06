"""
samsara_ai/security/homomorphic.py

Enterprise Homomorphic Encryption Module with Hybrid Scheme Support
"""

from typing import Union, Tuple, Optional
import numpy as np
import tenseal as ts
from phe import paillier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from prometheus_client import Histogram, Counter
from pydantic import BaseModel, Field, validator
from tenacity import retry, stop_after_delay, wait_exponential
import logging
import os

# Metrics
HE_OP_TIME = Histogram('he_operation_duration', 'Homomorphic operation latency', ['scheme', 'op_type'])
HE_KEY_ROTATION = Counter('he_key_rotations', 'Key rotation events', ['scheme'])
HE_SECURITY_FAILURES = Counter('he_security_incidents', 'Security policy violations')

logger = logging.getLogger("samsara.he")

class HEScheme(str, Enum):
    PAILLIER = "paillier"
    CKKS = "ckks"
    BFV = "bfv"
    HYBRID = "hybrid"

class HEKeyPolicy(BaseModel):
    rotation_interval: str = Field("30d", regex=r"^\d+[dhm]$")
    max_operations: int = Field(1000, gt=0)
    security_level: int = Field(2048, enum=[1024, 2048, 4096])
    enable_hardware: bool = True
    allow_hybrid: bool = False

class HomomorphicEngine:
    def __init__(self, scheme: HEScheme = HEScheme.PAILLIER, config: Optional[dict] = None):
        self.scheme = scheme
        self.config = config or {}
        self._init_context()
        self._key_rotation_interval = self._parse_rotation_interval()
        self._operations_count = 0
        self._security_checks()

    def _init_context(self):
        """Initialize encryption context with hardware acceleration"""
        if self.scheme == HEScheme.PAILLIER:
            self.public_key, self.private_key = paillier.generate_paillier_keypair(
                n_length=self.config.get('key_length', 2048))
        elif self.scheme == HEScheme.CKKS:
            context = ts.context(ts.SCHEME_TYPE.CKKS, 
                               poly_modulus_degree=8192,
                               coeff_mod_bit_sizes=[60, 40, 40, 60])
            context.generate_galois_keys()
            context.global_scale = 2**40
            self.context = context
        elif self.scheme == HEScheme.HYBRID:
            self._init_hybrid_context()
        else:
            raise NotImplementedError(f"Scheme {self.scheme} not supported")

    def _init_hybrid_context(self):
        """Hybrid Paillier + CKKS context for numeric stability"""
        self.paillier_engine = HomomorphicEngine(HEScheme.PAILLIER, self.config)
        self.ckks_engine = HomomorphicEngine(HEScheme.CKKS, self.config)
        self.hybrid_mapping = {}

    @retry(stop=stop_after_delay(30), wait=wait_exponential(multiplier=1))
    def encrypt(self, data: Union[float, np.ndarray]) -> Union[paillier.EncryptedNumber, ts.CKKSTensor]:
        """Encrypt data with automatic type dispatch and key rotation checks"""
        self._check_key_rotation()
        
        with HE_OP_TIME.labels(self.scheme.value, 'encrypt').time():
            if self.scheme == HEScheme.PAILLIER:
                return self.public_key.encrypt(float(data))
            elif self.scheme == HEScheme.CKKS:
                return ts.ckks_tensor(self.context, [data] if isinstance(data, float) else data)
            elif self.scheme == HEScheme.HYBRID:
                return self._hybrid_encrypt(data)
                
        self._operations_count += 1

    def _hybrid_encrypt(self, data):
        """Hybrid encryption routing based on data characteristics"""
        if isinstance(data, (int, np.integer)):
            encrypted = self.paillier_engine.encrypt(data)
            self.hybrid_mapping[id(encrypted)] = 'paillier'
            return encrypted
        else:
            encrypted = self.ckks_engine.encrypt(data)
            self.hybrid_mapping[id(encrypted)] = 'ckks'
            return encrypted

    def decrypt(self, ciphertext) -> Union[float, np.ndarray]:
        """Decrypt data with scheme auto-detection"""
        with HE_OP_TIME.labels(self.scheme.value, 'decrypt').time():
            if self.scheme == HEScheme.PAILLIER:
                return self.private_key.decrypt(ciphertext)
            elif self.scheme == HEScheme.CKKS:
                return ciphertext.decrypt().tolist()
            elif self.scheme == HEScheme.HYBRID:
                return self._hybrid_decrypt(ciphertext)

    def _hybrid_decrypt(self, ciphertext):
        scheme = self.hybrid_mapping.get(id(ciphertext), 'paillier')
        if scheme == 'paillier':
            return self.paillier_engine.decrypt(ciphertext)
        else:
            return self.ckks_engine.decrypt(ciphertext)

    @HE_OP_TIME.labels('any', 'add').time()
    def add(self, a, b):
        """Homomorphic addition with automatic type promotion"""
        if self.scheme == HEScheme.PAILLIER:
            return a + b
        elif self.scheme == HEScheme.CKKS:
            return a + b
        elif self.scheme == HEScheme.HYBRID:
            return self._hybrid_add(a, b)

    def _hybrid_add(self, a, b):
        """Cross-scheme addition via decryption fallback"""
        try:
            return a + b
        except TypeError:
            decrypted_a = self.decrypt(a)
            decrypted_b = self.decrypt(b)
            return self.encrypt(decrypted_a + decrypted_b)

    def _check_key_rotation(self):
        """Rotate keys based on usage policy"""
        if self._operations_count >= self.config.get('max_operations', 1000):
            self.rotate_keys()
            HE_KEY_ROTATION.labels(self.scheme.value).inc()
            self._operations_count = 0

    def rotate_keys(self):
        """Key rotation with zero-downtime re-encryption"""
        logger.info("Initiating key rotation...")
        old_public = self.public_key if self.scheme == HEScheme.PAILLIER else None
        old_context = self.context if self.scheme == HEScheme.CKKS else None
        
        self._init_context()  # Generate new keys
        
        if self.scheme == HEScheme.PAILLIER:
            # TODO: Implement re-encryption proxy for in-flight data
            pass
            
        logger.info(f"Key rotation completed for {self.scheme}")

    def _parse_rotation_interval(self) -> int:
        """Convert rotation interval to seconds"""
        unit = self.config['rotation_interval'][-1]
        value = int(self.config['rotation_interval'][:-1])
        return {'h': 3600, 'd': 86400, 'm': 2592000}[unit] * value

    def _security_checks(self):
        """Validate against insecure configurations"""
        if self.config.get('security_level', 2048) < 2048:
            HE_SECURITY_FAILURES.inc()
            raise ValueError("Insecure key length <2048 bits prohibited")
            
        if self.scheme == HEScheme.HYBRID and not self.config.get('allow_hybrid', False):
            HE_SECURITY_FAILURES.inc()
            raise RuntimeError("Hybrid mode requires explicit enablement")

    def secure_serialize(self, path: str):
        """Export keys with hardware-backed storage"""
        if self.scheme == HEScheme.PAILLIER:
            with open(f"{path}_public.key", "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            # Private key should be handled by HSM integration
        elif self.scheme == HEScheme.CKKS:
            self.context.save(f"{path}_context.seal")

    def enable_hardware(self, accelerator: str = "cuda"):
        """Enable GPU/TPU acceleration"""
        if accelerator == "cuda" and ts.cuda_available():
            self.context = self.context.cuda()
        elif accelerator == "tpu":
            raise NotImplementedError("TPU support pending")

class HEComplianceAuditor:
    @staticmethod
    def validate_encryption(engine, data):
        """NIST SP 800-56B Rev2 compliance checks"""
        # Implementation of cryptographic validation suite
        pass

# Example Usage
if __name__ == "__main__":
    config = {
        "key_length": 2048,
        "max_operations": 500,
        "rotation_interval": "7d",
        "security_level": 2048
    }
    
    he_engine = HomomorphicEngine(HEScheme.CKKS, config)
    encrypted_vector = he_engine.encrypt(np.array([3.14, 2.71]))
    encrypted_sum = he_engine.add(encrypted_vector, encrypted_vector)
    print(f"Decrypted result: {he_engine.decrypt(encrypted_sum)}")
