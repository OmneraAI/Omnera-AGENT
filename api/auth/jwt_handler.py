"""
samsara_ai/auth/jwt_handler.py

Enterprise JWT Manager with Automatic Key Rotation and Zero-Trust Validation
"""

import os
import time
import logging
import jwt
from jwt import PyJWKClient
from typing import Dict, Optional, Tuple
from functools import lru_cache
from pydantic import BaseModel, ValidationError
from prometheus_client import Counter, Histogram

# Configure logging
logging.basicConfig(format="%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s",
                   datefmt="%Y-%m-%d %H:%M:%S",
                   level=logging.INFO)
logger = logging.getLogger("samsara.jwt")

# Prometheus Metrics
JWT_ISSUED = Counter("samsara_jwt_issued_total", "Total issued JWTs", ["tenant", "algorithm"])
JWT_VALIDATED = Counter("samsara_jwt_validated_total", "JWT validation results", ["result"])
JWT_PROCESS_TIME = Histogram("samsara_jwt_process_seconds", "JWT processing time", ["operation"])

class TokenClaims(BaseModel):
    """Standardized JWT claims for Samsara AI ecosystem"""
    sub: str  # Agent/User ID
    tid: str  # Tenant ID
    aud: str  # Audience (Service Name)
    jti: str  # Unique Token ID
    scp: list[str] = ["samsara.agent.basic"]  # Scopes
    iss: str = "samsara-ai"
    iat: int = int(time.time())
    exp: int = int(time.time() + 3600)  # 1h default
    nbf: int = int(time.time())
    rev: int = 0  # Key Revision ID

class KeySetManager:
    """JWKS Management with automatic rotation"""
    def __init__(self, vault_endpoint: str, refresh_interval: int = 300):
        self.vault_endpoint = vault_endpoint
        self.refresh_interval = refresh_interval
        self.last_updated = 0
        self._current_keys = {}
        
    def refresh_keys(self):
        """Fetch latest keys from Vault with error handling"""
        if time.time() - self.last_updated < self.refresh_interval:
            return
            
        try:
            # Example: Integrate with HashiCorp Vault PKI
            # response = requests.get(f"{self.vault_endpoint}/v1/samsara/jwks")
            # self._current_keys = response.json()["keys"]
            
            # Mock new key generation
            new_key = {
                "kty": "RSA",
                "kid": f"key_{int(time.time())}",
                "use": "sig",
                "alg": "RS256",
                "n": "mock_public_modulus",
                "e": "AQAB"
            }
            self._current_keys = {"keys": [new_key]}
            self.last_updated = time.time()
            logger.info("JWKS keys rotated successfully")
            
        except Exception as e:
            logger.error(f"Key rotation failed: {str(e)}")
            raise KeyRotationError("JWKS update failure")

    @property
    def jwks(self) -> Dict:
        self.refresh_keys()
        return self._current_keys

class JWTManager:
    """Core JWT Processor with Defense-in-Depth"""
    def __init__(self, vault_endpoint: str, redis_conn=None):
        self.keyset = KeySetManager(vault_endpoint)
        self.redis = redis_conn  # For token revocation list
        self.algorithms = ["RS256", "HS256"]  # Ordered by preference
        
    @JWT_PROCESS_TIME.time()
    def generate_token(self, claims: TokenClaims, algorithm: str = "RS256") -> str:
        """Generate JWT with current active key"""
        if algorithm not in self.algorithms:
            raise InvalidAlgorithmError(f"Unsupported algorithm: {algorithm}")
            
        header = {
            "typ": "JWT",
            "alg": algorithm,
            "kid": self.keyset.jwks["keys"][0]["kid"]
        }
        
        payload = claims.dict()
        secret = self._get_signing_key(algorithm)
        
        try:
            token = jwt.encode(payload, secret, algorithm=algorithm, headers=header)
            JWT_ISSUED.labels(tenant=claims.tid, algorithm=algorithm).inc()
            logger.info(f"Issued token {claims.jti} for {claims.aud}")
            return token
        except Exception as e:
            logger.error(f"Token generation error: {str(e)}")
            raise TokenGenerationError("JWT creation failure")

    @JWT_PROCESS_TIME.time()
    def validate_token(self, token: str, audience: str) -> Tuple[bool, Optional[TokenClaims]]:
        """Full-chain JWT validation with revocation check"""
        try:
            # Step 1: Check revocation list
            if self._is_revoked(token):
                raise TokenRevokedError("Token in blocklist")
                
            # Step 2: Decode header to get key ID
            unverified = jwt.get_unverified_header(token)
            jwks_client = PyJWKClient(self.keyset.jwks)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            
            # Step 3: Full validation
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=audience,
                issuer="samsara-ai",
                leeway=30
            )
            
            # Step 4: Custom claims validation
            claims = TokenClaims(**payload)
            self._validate_claims(claims)
            
            JWT_VALIDATED.labels(result="valid").inc()
            return True, claims
            
        except jwt.ExpiredSignatureError:
            JWT_VALIDATED.labels(result="expired").inc()
            raise TokenExpiredError("JWT expired")
        except jwt.PyJWTError as e:
            JWT_VALIDATED.labels(result="invalid").inc()
            logger.warning(f"Invalid token: {str(e)}")
            raise InvalidTokenError("JWT validation failed")
        except ValidationError as e:
            JWT_VALIDATED.labels(result="invalid_claims").inc()
            logger.warning(f"Claim validation failed: {str(e)}")
            raise InvalidClaimsError("Invalid JWT claims")

    def revoke_token(self, token: str, expire_after: int = 3600) -> None:
        """Add token to revocation list with TTL"""
        jti = jwt.decode(token, options={"verify_signature": False})["jti"]
        self.redis.setex(f"jti:{jti}", expire_after, "revoked")
        logger.info(f"Revoked token {jti}")

    def _get_signing_key(self, algorithm: str) -> str:
        """Retrieve appropriate signing key"""
        if algorithm.startswith("RS"):
            return self.keyset.jwks["keys"][0]["private_key"]  # Mock for illustration
        elif algorithm == "HS256":
            return os.getenv("JWT_HS256_SECRET")  # From secure storage
        else:
            raise InvalidAlgorithmError("Unsupported algorithm")

    def _is_revoked(self, token: str) -> bool:
        """Check revocation status via Redis"""
        if not self.redis:
            return False
            
        try:
            jti = jwt.decode(token, options={"verify_signature": False})["jti"]
            return self.redis.exists(f"jti:{jti}") == 1
        except Exception as e:
            logger.error(f"Revocation check failed: {str(e)}")
            return False

    def _validate_claims(self, claims: TokenClaims) -> None:
        """Custom claims validation logic"""
        if claims.rev < int(os.getenv("MIN_KEY_REV", 0)):
            raise KeyRevisionError("Stale signing key detected")
            
        if "samsara.admin" in claims.scp and not claims.tid.startswith("admin"):
            raise PrivilegeEscalationError("Invalid admin scope")

# Custom Exceptions
class JWTError(Exception):
    """Base JWT exception"""
    
class TokenExpiredError(JWTError):
    pass
    
class InvalidTokenError(JWTError):
    pass
    
class KeyRotationError(JWTError):
    pass
    
class TokenRevokedError(JWTError):
    pass
    
class InvalidClaimsError(JWTError):
    pass
    
class PrivilegeEscalationError(JWTError):
    pass

# Example Usage
if __name__ == "__main__":
    # Initialize with mock Vault and Redis
    manager = JWTManager(vault_endpoint="http://vault:8200")
    
    # Generate token
    claims = TokenClaims(
        sub="agent-123",
        tid="tenant-xyz",
        aud="samsara-api",
        jti="unique-id-123",
        scp=["samsara.agent.write"]
    )
    
    token = manager.generate_token(claims)
    print(f"Generated Token: {token}")
    
    # Validate token
    try:
        valid, decoded = manager.validate_token(token, audience="samsara-api")
        print(f"Token valid: {valid}, Claims: {decoded}")
    except JWTError as e:
        print(f"Validation failed: {str(e)}")
