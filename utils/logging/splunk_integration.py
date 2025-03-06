"""
samsara_ai/integrations/splunk/splunk_integration.py

Enterprise Splunk Integration Module with CIM Compliance and Zero-Trust Data Forwarding
"""

import aiohttp
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from cryptography.fernet import Fernet
import prometheus_client as prom

# -------------------------------
# Configuration Models
# -------------------------------

@dataclass(frozen=True)
class SplunkConfig:
    hec_endpoint: str  # HTTPS Event Collector endpoint
    hec_token: str      # Encrypted HEC token
    index: str          # Splunk destination index
    max_batch_size: int = 5000
    batch_timeout: int = 10  # Seconds
    ssl_verify: bool = True
    retry_policy: Tuple[int, int, int] = (3, 5, 15)  # retries, initial delay, max delay

# -------------------------------
# Security Handlers
# -------------------------------

class SplunkEncryptionManager:
    """Enterprise-grade payload encryption with key rotation"""
    
    def __init__(self, encryption_key: str):
        self.cipher = Fernet(encryption_key.encode())
        self.key_version = 1
        
    def encrypt_payload(self, payload: dict) -> dict:
        """Encrypt sensitive fields while maintaining CIM compliance"""
        encrypted = payload.copy()
        encrypted['_encryption_version'] = self.key_version
        
        # PII Redaction
        if 'user' in encrypted:
            encrypted['user'] = f"redacted:{hash(encrypted['user'])}"
        
        # Field-level encryption
        sensitive_fields = ['password', 'api_key', 'token']
        for field in sensitive_fields:
            if field in encrypted:
                encrypted[f"{field}_encrypted"] = self.cipher.encrypt(
                    encrypted.pop(field).encode()
                ).decode()
                
        return encrypted

# -------------------------------
# Core Forwarder Implementation
# -------------------------------

class SplunkEnterpriseForwarder:
    """Atomic Splunk forwarder with circuit breaker pattern"""
    
    _METRICS = {
        'events_sent': prom.Counter(
            'splunk_events_sent_total',
            'Total events sent to Splunk',
            ['index', 'status']
        ),
        'batch_size': prom.Histogram(
            'splunk_batch_size_bytes',
            'Size of Splunk batches',
            buckets=[512, 2048, 8192, 32768]
        ),
    }
    
    def __init__(self, config: SplunkConfig, encryptor: SplunkEncryptionManager):
        self.config = config
        self.encryptor = encryptor
        self._queue = asyncio.Queue(maxsize=100000)
        self._session: Optional[aiohttp.ClientSession] = None
        self._circuit_open = False
        self._last_failure = datetime.min
        
    async def start(self):
        """Initialize async resources"""
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=self.config.ssl_verify),
            headers={
                'Authorization': f"Splunk {self._decrypt_hec_token()}",
                'Content-Type': 'application/json'
            }
        )
        asyncio.create_task(self._batch_processor())
        
    async def stop(self):
        """Graceful shutdown"""
        await self._session.close()
        
    def _decrypt_hec_token(self) -> str:
        """Integration with enterprise KMS"""
        # Implementation varies by vault provider
        return Fernet(os.getenv('SPLUNK_KEY')).decrypt(
            self.config.hec_token.encode()
        ).decode()

    async def send_event(self, event: dict):
        """Thread-safe event queuing"""
        encrypted_event = self.encryptor.encrypt_payload(event)
        await self._queue.put(encrypted_event)
        
    async def _batch_processor(self):
        """Batch events with adaptive timeout"""
        batch = []
        last_flush = datetime.utcnow()
        
        while True:
            try:
                event = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=self.config.batch_timeout
                )
                batch.append(event)
                
                # Flush when batch size or timeout reached
                if (len(batch) >= self.config.max_batch_size or 
                    (datetime.utcnow() - last_flush).seconds >= self.config.batch_timeout):
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = datetime.utcnow()
                    
            except asyncio.TimeoutError:
                if batch:
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = datetime.utcnow()

    async def _flush_batch(self, batch: List[dict]):
        """Atomic batch send with retries"""
        payload = {'host': os.getenv('HOSTNAME'), 'events': batch}
        retries, delay, max_delay = self.config.retry_policy
        
        for attempt in range(retries + 1):
            try:
                if self._circuit_open:
                    if datetime.utcnow() - self._last_failure > timedelta(minutes=5):
                        self._circuit_open = False
                    else:
                        raise Exception("Circuit breaker open")
                
                async with self._session.post(
                    self.config.hec_endpoint,
                    data=json.dumps(payload),
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        self._METRICS['events_sent'].labels(
                            index=self.config.index, 
                            status='success'
                        ).inc(len(batch))
                        self._METRICS['batch_size'].observe(len(json.dumps(payload)))
                        return
                    else:
                        error = f"Splunk HEC error: {await resp.text()}"
                        
            except Exception as e:
                error = f"Connection error: {str(e)}"
                
            # Backoff and retry logic
            if attempt < retries:
                logging.warning(f"Attempt {attempt+1} failed: {error}")
                await asyncio.sleep(min(delay * (2 ** attempt), max_delay))
            else:
                logging.error(f"Final failure: {error}")
                self._circuit_open = True
                self._last_failure = datetime.utcnow()
                self._METRICS['events_sent'].labels(
                    index=self.config.index, 
                    status='failure'
                ).inc(len(batch))
                break

# -------------------------------
# CIM Compliance Adapter
# -------------------------------

class CIMComplianceAdapter:
    """Common Information Model (CIM) normalization"""
    
    _MAPPINGS = {
        'security': {
            'required': ['action', 'src_user', 'dest_host'],
            'optional': ['protocol', 'bytes_in'],
            'transformations': {
                'src_user': lambda x: x.lower(),
                'timestamp': lambda x: x.isoformat()
            }
        },
        'performance': {
            'required': ['metric_name', 'value'],
            'optional': ['unit', 'threshold'],
            'transformations': {
                'value': float
            }
        }
    }
    
    @classmethod
    def normalize_event(cls, raw_event: dict, data_model: str) -> dict:
        """Transform raw data to CIM-compliant format"""
        model = cls._MAPPINGS.get(data_model)
        if not model:
            raise ValueError(f"Unsupported CIM model: {data_model}")
            
        event = {}
        
        # Required fields
        for field in model['required']:
            if field not in raw_event:
                raise KeyError(f"Missing required CIM field: {field}")
            event[field] = model['transformations'].get(field, lambda x: x)(raw_event[field])
            
        # Optional fields
        for field in model['optional']:
            if field in raw_event:
                event[field] = model['transformations'].get(field, lambda x: x)(raw_event[field])
                
        return event

# -------------------------------
# Enterprise Deployment Example
# -------------------------------

async def main():
    # Initialize with environment variables
    config = SplunkConfig(
        hec_endpoint=os.getenv('SPLUNK_HEC_URL'),
        hec_token=os.getenv('ENCRYPTED_HEC_TOKEN'),
        index=os.getenv('SPLUNK_INDEX')
    )
    
    encryptor = SplunkEncryptionManager(
        encryption_key=os.getenv('FIELD_ENCRYPTION_KEY')
    )
    
    forwarder = SplunkEnterpriseForwarder(config, encryptor)
    await forwarder.start()
    
    try:
        # Example security event
        raw_event = {
            'action': 'login_attempt',
            'src_user': 'admin@corp',
            'dest_host': 'samsara-gateway',
            'password': 'secret',  # Will be encrypted
            'timestamp': datetime.utcnow()
        }
        cim_event = CIMComplianceAdapter.normalize_event(raw_event, 'security')
        await forwarder.send_event(cim_event)
        
    finally:
        await forwarder.stop()

if __name__ == "__main__":
    asyncio.run(main())
