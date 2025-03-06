"""
samsara_ai/auth/oauth2_schema.py

Enterprise OAuth 2.0 Implementation with PCI-DSS Compliance Controls
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
from enum import Enum
import hashlib
import secrets
import logging
from prometheus_client import Counter, Histogram

# Configure logging
logging.basicConfig(format="%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s",
                   datefmt="%Y-%m-%d %H:%M:%S",
                   level=logging.INFO)
logger = logging.getLogger("samsara.oauth")

# Prometheus Metrics
OAUTH_TOKENS_ISSUED = Counter("samsara_oauth_tokens_issued", "OAuth tokens issued", ["grant_type", "client_type"])
OAUTH_FAILURES = Counter("samsara_oauth_failures", "Authentication failures", ["error_type"])
OAUTH_PROCESS_TIME = Histogram("samsara_oauth_process_seconds", "OAuth processing time", ["operation"])

class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"

class ClientType(str, Enum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"
    SYSTEM = "system"

class TokenType(str, Enum):
    BEARER = "Bearer"
    MAC = "MAC"

class OAuthClient(BaseModel):
    """Dynamic client registration model"""
    client_id: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    client_secret: Optional[str] = None
    client_type: ClientType = ClientType.CONFIDENTIAL
    grant_types: List[GrantType] = [GrantType.CLIENT_CREDENTIALS]
    redirect_uris: List[str] = []
    scopes: List[str] = ["samsara.agent.read"]
    tenant_id: str = Field(..., min_length=3)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    rotated_at: Optional[datetime] = None
    jwks_uri: Optional[str] = None
    token_endpoint_auth_method: str = "client_secret_basic"
    software_statement: Optional[str] = None

    @validator('client_secret', always=True)
    def validate_secret(cls, v, values):
        if values.get('client_type') == ClientType.CONFIDENTIAL and not v:
            return secrets.token_urlsafe(64)
        return v

class TokenRequest(BaseModel):
    """RFC 6749 Section 4.1.1 compliant request"""
    grant_type: GrantType
    client_id: str
    client_secret: Optional[str] = None
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[List[str]] = None
    code_verifier: Optional[str] = None
    audience: Optional[str] = None

class TokenResponse(BaseModel):
    """RFC 6749 Section 4.1.4 compliant response"""
    access_token: str
    token_type: TokenType = TokenType.BEARER
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    scope: Optional[List[str]] = None
    issued_token_type: Optional[str] = "urn:ietf:params:oauth:token-type:access_token"

class TokenIntrospection(BaseModel):
    """RFC 7662 compliant response"""
    active: bool
    scope: Optional[List[str]] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    iss: Optional[str] = None
    jti: Optional[str] = None

class OAuthManager:
    """Enterprise OAuth 2.0 provider with security controls"""
    def __init__(self, redis_conn, jwks_manager):
        self.redis = redis_conn
        self.jwks_manager = jwks_manager
        self.clients = {}  # In-memory cache, use persistent storage in production

    @OAUTH_PROCESS_TIME.time()
    def register_client(self, client: OAuthClient) -> OAuthClient:
        """Dynamic client registration with security vetting"""
        if client.software_statement:
            self._validate_software_statement(client.software_statement)
            
        client_hash = self._hash_credentials(client.client_id, client.client_secret)
        self.redis.hset(f"oauth:clients:{client.tenant_id}", client_hash, client.json())
        self.clients[client.client_id] = client
        logger.info(f"Registered client {client.client_id} for tenant {client.tenant_id}")
        return client

    @OAUTH_PROCESS_TIME.time()
    def issue_token(self, request: TokenRequest) -> TokenResponse:
        """Core token issuance with security validations"""
        client = self._authenticate_client(request.client_id, request.client_secret)
        self._validate_grant(client, request)
        
        token = self._generate_token(client, request.scope)
        response = TokenResponse(
            access_token=token["access_token"],
            refresh_token=token.get("refresh_token"),
            scope=token["scope"],
            expires_in=token["expires_in"]
        )
        
        OAUTH_TOKENS_ISSUED.labels(grant_type=request.grant_type.value, client_type=client.client_type.value).inc()
        return response

    def introspect_token(self, token: str) -> TokenIntrospection:
        """Token validation with revocation check"""
        stored = self.redis.get(f"oauth:tokens:{token}")
        if not stored:
            return TokenIntrospection(active=False)
            
        token_data = self.jwks_manager.validate_token(token)
        revoked = self.redis.exists(f"oauth:revoked:{token}")
        return TokenIntrospection(
            active=not revoked and token_data["exp"] > datetime.utcnow().timestamp(),
            scope=token_data.get("scope"),
            client_id=token_data.get("client_id"),
            exp=token_data.get("exp"),
            iat=token_data.get("iat")
        )

    def revoke_token(self, token: str) -> None:
        """Immediate token revocation"""
        self.redis.setex(f"oauth:revoked:{token}", 86400, "1")
        logger.info(f"Revoked token {token}")

    def _authenticate_client(self, client_id: str, secret: str) -> OAuthClient:
        """Client authentication with multiple methods support"""
        client = self.clients.get(client_id) or self._load_client(client_id)
        if not client:
            OAUTH_FAILURES.labels(error_type="invalid_client").inc()
            raise InvalidClientError("Client not registered")
            
        if client.client_type == ClientType.CONFIDENTIAL and not self._verify_secret(client, secret):
            OAUTH_FAILURES.labels(error_type="invalid_secret").inc()
            raise InvalidSecretError("Client secret mismatch")
            
        return client

    def _validate_grant(self, client: OAuthClient, request: TokenRequest):
        """Grant type specific validations"""
        if request.grant_type not in client.grant_types:
            OAUTH_FAILURES.labels(error_type="unauthorized_grant").inc()
            raise UnauthorizedGrantError("Grant type not allowed")

    def _generate_token(self, client: OAuthClient, scopes: List[str]) -> Dict:
        """Token generation with scoped access"""
        token_data = {
            "sub": client.client_id,
            "aud": "samsara-api",
            "iss": "samsara-oauth",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=3600),
            "scope": self._validate_scopes(client.scopes, scopes),
            "client_id": client.client_id,
            "tenant_id": client.tenant_id
        }
        
        token = self.jwks_manager.generate_token(token_data)
        self.redis.setex(f"oauth:tokens:{token}", 3600, token_data)
        return {"access_token": token, "scope": scopes, "expires_in": 3600}

    def _validate_scopes(self, allowed: List[str], requested: List[str]) -> List[str]:
        """Scope validation with least privilege"""
        if not requested:
            return allowed
            
        invalid = set(requested) - set(allowed)
        if invalid:
            OAUTH_FAILURES.labels(error_type="invalid_scope").inc()
            raise InvalidScopeError(f"Invalid scopes: {invalid}")
        return requested

    def _hash_credentials(self, client_id: str, secret: str) -> str:
        """Secure credential hashing"""
        return hashlib.blake2b(f"{client_id}:{secret}".encode(), key=os.getenv("HASH_PEPPER").encode()).hexdigest()

# Custom Exceptions
class OAuthError(Exception):
    """Base OAuth exception"""
    
class InvalidClientError(OAuthError):
    pass
    
class InvalidSecretError(OAuthError):
    pass
    
class UnauthorizedGrantError(OAuthError):
    pass
    
class InvalidScopeError(OAuthError):
    pass

# Example Usage
if __name__ == "__main__":
    # Initialize with mock dependencies
    from redis import Redis
    from jwt_handler import JWTManager
    
    redis = Redis()
    jwks = JWTManager(vault_endpoint="http://vault:8200")
    oauth = OAuthManager(redis, jwks)
    
    # Register client
    client = OAuthClient(
        tenant_id="tenant-xyz",
        client_type=ClientType.CONFIDENTIAL,
        grant_types=[GrantType.CLIENT_CREDENTIALS],
        scopes=["samsara.agent.admin"]
    )
    registered = oauth.register_client(client)
    
    # Issue token
    token = oauth.issue_token(TokenRequest(
        grant_type=GrantType.CLIENT_CREDENTIALS,
        client_id=registered.client_id,
        client_secret=registered.client_secret
    ))
    print(f"Issued token: {token.access_token}")
    
    # Introspect token
    print(oauth.introspect_token(token.access_token))
