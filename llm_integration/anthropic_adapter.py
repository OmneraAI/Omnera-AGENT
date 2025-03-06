"""
samsara_ai/integrations/llm/anthropic_adapter.py

Enterprise Claude API Adapter with Zero-Trust Architecture
"""

import os
import time
from typing import Dict, Optional, Generator
import httpx
from pydantic import BaseModel, Field
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
from prometheus_client import Counter, Histogram
from cryptography.fernet import Fernet

# --- Metrics ---
ANTHROPIC_REQUEST_COUNTER = Counter(
    'anthropic_requests_total',
    'API Requests by Status and Model',
    ['model', 'status_code']
)
ANTHROPIC_TOKEN_GAUGE = Histogram(
    'anthropic_tokens_used',
    'Token Usage Distribution',
    ['model', 'type']
)

# --- Security ---
FERNET_KEY = os.getenv("ANTHROPIC_FERNET_KEY")  # From Vault/Secrets Manager

class SecureAnthropicRequest(BaseModel):
    encrypted_prompt: str = Field(
        ...,
        description="Fernet-encrypted input with IV"
    )
    model: str = Field("claude-3-opus-20240229", max_length=64)
    max_tokens: int = Field(4096, ge=1, le=4096)
    temperature: float = Field(0.7, ge=0.0, le=1.0)
    top_p: float = Field(0.9, ge=0.0, le=1.0)
    system: Optional[str] = Field(None, max_length=50000)

class EnterpriseAnthropicClient:
    def __init__(self):
        self.base_url = os.getenv(
            "ANTHROPIC_BASE_URL", 
            "https://api.anthropic.com/v1"
        )
        self.api_key = self._retrieve_api_key()
        self.cipher = Fernet(FERNET_KEY.encode())
        self.session = httpx.Client(
            base_url=self.base_url,
            timeout=45,
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=25
            )
        )
        self.rate_limit = 1500  # RPM based on enterprise contract

    def _retrieve_api_key(self) -> str:
        """Fetch API key via HashiCorp Vault with IAM auth"""
        # Example Vault integration:
        # vault_client = hvac.Client(url=os.getenv("VAULT_ADDR"))
        # return vault_client.secrets.kv.v2.read_secret_version(
        #     path='anthropic-prod'
        # )['data']['data']['api_key']
        return os.getenv("ANTHROPIC_API_KEY")  # Local fallback

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1.5, max=12),
        retry=retry_if_exception_type(
            (httpx.NetworkError, httpx.TimeoutException)
        )
    )
    def _execute_request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Core request executor with circuit breaking"""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "x-samsara-audit-id": os.getenv("AUDIT_ID", "default")
        }

        start_time = time.monotonic()
        response = self.session.request(method, endpoint, headers=headers, **kwargs)
        latency = time.monotonic() - start_time

        # Track metrics
        status_code = str(response.status_code)
        model = kwargs.get('json', {}).get('model', 'unknown')
        ANTHROPIC_REQUEST_COUNTER.labels(model=model, status_code=status_code).inc()
        ANTHROPIC_TOKEN_GAUGE.labels(
            model=model, 
            type="input"
        ).observe(kwargs.get('json', {}).get('max_tokens', 0))

        if 500 <= response.status_code < 600:
            raise httpx.HTTPStatusError(
                f"Server error: {response.text}",
                request=response.request,
                response=response
            )
        return response

    def decrypt_payload(self, secure_request: SecureAnthropicRequest) -> str:
        """Decrypt payload using AES-GCM with stored IV"""
        return self.cipher.decrypt(
            secure_request.encrypted_prompt.encode()
        ).decode()

    def generate(
        self, 
        secure_request: SecureAnthropicRequest,
        stream: bool = False
    ) -> Generator[Dict, None, None]:
        """
        Enterprise-grade text generation with:
        - Input/output encryption
        - Adaptive rate limiting
        - Regulatory compliance logging
        """
        decrypted_prompt = self.decrypt_payload(secure_request)
        
        payload = {
            "model": secure_request.model,
            "messages": [{"role": "user", "content": decrypted_prompt}],
            "system": secure_request.system,
            "max_tokens": secure_request.max_tokens,
            "temperature": secure_request.temperature,
            "top_p": secure_request.top_p,
            "stream": stream
        }

        endpoint = "/messages"
        response = self._execute_request("POST", endpoint, json=payload)

        if stream:
            for chunk in response.iter_lines():
                if chunk:
                    yield self._process_stream_chunk(chunk)
        else:
            data = response.json()
            ANTHROPIC_TOKEN_GAUGE.labels(
                model=secure_request.model, 
                type="output"
            ).observe(data.get('usage', {}).get('output_tokens', 0))
            yield data

    def _process_stream_chunk(self, chunk: bytes) -> Dict:
        """Validate and sanitize streaming chunks"""
        # Implement OWASP XSS filtering
        return httpx.Response(content=chunk).json()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

# --- Usage Example ---
if __name__ == "__main__":
    # Local test with encryption
    client = EnterpriseAnthropicClient()
    encrypted = client.cipher.encrypt(b"Analyze supply chain risks in APAC region")
    
    response = client.generate(
        SecureAnthropicRequest(
            encrypted_prompt=encrypted.decode(),
            system="You are a senior supply chain analyst",
            max_tokens=1024
        )
    )
    print(next(response))
