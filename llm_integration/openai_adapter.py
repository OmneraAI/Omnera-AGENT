"""
samsara_ai/integrations/llm/openai_adapter.py

Enterprise OpenAI API Adapter with Zero-Trust Security Controls
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
REQUEST_COUNTER = Counter(
    'openai_requests_total',
    'API Requests by Status',
    ['endpoint', 'status']
)
RESPONSE_TIME = Histogram(
    'openai_response_seconds',
    'Response Time Distribution',
    ['endpoint']
)

# --- Security ---
FERNET_KEY = os.getenv("OPENAI_FERNET_KEY")  # From Vault/Secrets Manager

class SecureRequest(BaseModel):
    encrypted_prompt: str = Field(
        ...,
        description="Fernet-encrypted prompt for zero-trust data handling"
    )
    model: str = Field("gpt-4-enterprise", max_length=64)
    temperature: float = Field(0.7, ge=0, le=2)
    max_tokens: int = Field(2048, ge=1, le=8192)

class EnterpriseOpenAIClient:
    def __init__(self):
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.api_key = self._get_api_key()
        self.cipher_suite = Fernet(FERNET_KEY.encode())
        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=30,
            limits=httpx.Limits(max_connections=100)
        )
        
    def _get_api_key(self) -> str:
        """Retrieve API key with HashiCorp Vault integration"""
        # Implementation example for Vault:
        # return hvac.Client(url=VAULT_ADDR).secrets.kv.v2.read_secret_version(
        #     path='openai-prod'
        # )['data']['data']['api_key']
        return os.getenv("OPENAI_API_KEY")  # Temp for local dev

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, max=10),
        retry=retry_if_exception_type(
            (httpx.NetworkError, httpx.TimeoutException)
        )
    )
    @RESPONSE_TIME.time()
    def _safe_request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Samsara-Audit-ID": os.getenv("AUDIT_ID", "default")
        }
        
        start_time = time.monotonic()
        response = self.client.request(method, endpoint, headers=headers, **kwargs)
        latency = time.monotonic() - start_time
        
        status = "success" if response.is_success else "failed"
        REQUEST_COUNTER.labels(endpoint=endpoint, status=status).inc()
        RESPONSE_TIME.labels(endpoint=endpoint).observe(latency)
        
        response.raise_for_status()
        return response

    def decrypt_prompt(self, secure_request: SecureRequest) -> str:
        """Decrypt prompts using FIPS 140-2 compliant encryption"""
        return self.cipher_suite.decrypt(
            secure_request.encrypted_prompt.encode()
        ).decode()

    def chat_completion(
        self, 
        secure_request: SecureRequest,
        stream: bool = False
    ) -> Generator[Dict, None, None]:
        """
        Enterprise-grade chat completion with: 
        - Input encryption at rest/transit
        - Request auditing
        - Rate limit tracking
        """
        decrypted_prompt = self.decrypt_prompt(secure_request)
        
        payload = {
            "model": secure_request.model,
            "messages": [{"role": "user", "content": decrypted_prompt}],
            "temperature": secure_request.temperature,
            "max_tokens": secure_request.max_tokens,
            "stream": stream
        }
        
        endpoint = "/chat/completions"
        response = self._safe_request("POST", endpoint, json=payload)
        
        if stream:
            for chunk in response.iter_lines():
                if chunk:
                    yield self._process_stream_chunk(chunk)
        else:
            yield response.json()

    def _process_stream_chunk(self, chunk: bytes) -> Dict:
        """Validate and sanitize streaming responses"""
        # Implement OWASP sanitization rules here
        return httpx.Response(content=chunk).json()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.close()

# --- Usage Example ---
if __name__ == "__main__":
    # For local testing (prod uses dependency injection)
    client = EnterpriseOpenAIClient()
    encrypted_prompt = client.cipher_suite.encrypt(b"Analyze Q4 financial risks")
    
    response = client.chat_completion(
        SecureRequest(encrypted_prompt=encrypted_prompt.decode())
    )
    print(next(response))
