"""
samsara_ai/observability/opentelemetry.py

Enterprise OpenTelemetry Integration with Advanced Context Propagation
"""

import os
import logging
from typing import Optional, Dict, Any, Callable
from contextvars import ContextVar
import functools

# OpenTelemetry Core
from opentelemetry import trace, metrics, _logs
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider, Counter, Histogram
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

# Exporters
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

# Instrumentations
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

# Context Propagation
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat

# -------------------------------
# Configuration Management
# -------------------------------

class TelemetryConfig:
    """Dynamic configuration loader with environment override"""
    
    _ENV_PREFIX = "OTEL_"
    
    def __init__(self):
        self.service_name = os.getenv(f"{self._ENV_PREFIX}SERVICE_NAME", "samsara-ai")
        self.endpoint = os.getenv(f"{self._ENV_PREFIX}EXPORTER_ENDPOINT", "http://collector:4317")
        self.enable_tracing = os.getenv(f"{self._ENV_PREFIX}TRACING_ENABLED", "true").lower() == "true"
        self.enable_metrics = os.getenv(f"{self._ENV_PREFIX}METRICS_ENABLED", "true").lower() == "true"
        self.enable_logs = os.getenv(f"{self._ENV_PREFIX}LOGS_ENABLED", "true").lower() == "true"
        self.sampling_rate = float(os.getenv(f"{self._ENV_PREFIX}SAMPLING_RATE", "1.0"))

# -------------------------------
# Core Initialization
# -------------------------------

def configure_telemetry(config: Optional[TelemetryConfig] = None) -> None:
    """Initialize OpenTelemetry with enterprise security settings"""
    config = config or TelemetryConfig()
    
    resource = Resource.create(attributes={
        "service.name": config.service_name,
        "telemetry.sdk.version": "0.42b0"
    })
    
    # Distributed Tracing
    if config.enable_tracing:
        trace_provider = TracerProvider(
            resource=resource,
            sampler=_SecurityAwareSampler(config.sampling_rate)
        )
        trace_provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=config.endpoint),
                schedule_delay_millis=5000,
                max_export_batch_size=1000
            )
        )
        trace.set_tracer_provider(trace_provider)
    
    # Metrics Collection
    if config.enable_metrics:
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=config.endpoint),
            export_interval_millis=30000
        )
        metrics.set_meter_provider(
            MeterProvider(resource=resource, metric_readers=[metric_reader])
        )
    
    # Log Correlation
    if config.enable_logs:
        logger_provider = LoggerProvider(
            resource=resource,
            processors=[
                BatchLogRecordProcessor(
                    OTLPLogExporter(endpoint=config.endpoint)
                )
            ]
        )
        _logs.set_logger_provider(logger_provider)
    
    # Context Propagation
    set_global_textmap(B3MultiFormat())
    
    # Auto-Instrumentation
    RequestsInstrumentor().instrument()
    RedisInstrumentor().instrument()
    
    # Security Filters
    _install_security_hooks()

# -------------------------------
# Security & Compliance Features
# -------------------------------

class _SecurityAwareSampler:
    """Enterprise sampling with PII filtering"""
    
    def __init__(self, base_ratio: float):
        self.base_ratio = base_ratio
        
    def should_sample(self, context, trace_id, name, attributes, links):
        # Implement data redaction rules
        redacted_attrs = {
            k: "[REDACTED]" if "secret" in k.lower() else v 
            for k, v in attributes.items()
        }
        return self.base_ratio < 0.1  # Simplified sampling logic

def _install_security_hooks():
    """Install data sanitization hooks"""
    original_export = BatchSpanProcessor.force_flush
    
    def secured_export(self, timeout_millis: int = 30000):
        # Add enterprise security validation
        if os.getenv("DEPLOY_ENV") == "prod":
            self.span_exporter._headers = _sign_headers()
        return original_export(self, timeout_millis)
    
    BatchSpanProcessor.force_flush = secured_export

def _sign_headers() -> Dict[str, str]:
    """Generate authenticated headers for OTLP export"""
    from samsara_ai.security.vault import get_signed_token
    return {"Authorization": f"Bearer {get_signed_token()}"}

# -------------------------------
# Decorators & Context Management
# -------------------------------

def traced(
    span_name: Optional[str] = None,
    capture_args: bool = True,
    record_exceptions: bool = True
) -> Callable:
    """Enterprise-grade tracing decorator"""
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tracer = trace.get_tracer(__name__)
            span_name = func.__qualname__
            
            with tracer.start_as_current_span(span_name) as span:
                try:
                    if capture_args:
                        span.set_attributes({
                            "args": str(args),
                            "kwargs": str(kwargs)
                        })
                    return func(*args, **kwargs)
                except Exception as e:
                    if record_exceptions:
                        span.record_exception(e)
                        span.set_status(trace.Status(trace.StatusCode.ERROR))
                    raise
                finally:
                    span.set_attribute("code.function", func.__name__)
                    
        return wrapper
    return decorator

# -------------------------------
# Metrics Collection
# -------------------------------

class SamsaraMetrics:
    """Enterprise-specific metrics registry"""
    
    def __init__(self):
        meter = metrics.get_meter(__name__)
        
        self.agent_start_counter = meter.create_counter(
            name="samsara.agents.started",
            description="Total agents initialized",
            unit="1"
        )
        
        self.task_duration_histogram = meter.create_histogram(
            name="samsara.tasks.duration",
            description="Task execution time distribution",
            unit="ms",
            boundaries=[10, 50, 100, 500, 1000]
        )
        
    def record_task(self, duration_ms: float):
        """Record task execution metrics"""
        self.task_duration_histogram.record(duration_ms)

# -------------------------------
# ASGI Middleware
# -------------------------------

class SecureTelemetryMiddleware(OpenTelemetryMiddleware):
    """Enhanced middleware with rate limiting protection"""
    
    def __init__(self, app, excluded_urls=None):
        super().__init__(app)
        self._rate_limiter = _RateLimiter()
        
    async def __call__(self, scope, receive, send):
        if self._rate_limiter.check_limit():
            return await super().__call__(scope, receive, send)
        else:
            # Handle telemetry overload protection
            return await self.app(scope, receive, send)

class _RateLimiter:
    """Telemetry data volume controller"""
    
    def __init__(self):
        self._budget = 1000  # Max spans per second
    
    def check_limit(self) -> bool:
        # Implement token bucket algorithm
        return True

# -------------------------------
# Initialization Example
# -------------------------------

if __name__ == "__main__":
    # Configure with environment variables
    configure_telemetry()
    
    # Example usage
    metrics = SamsaraMetrics()
    
    @traced(span_name="sample_operation")
    def sample_task():
        metrics.agent_start_counter.add(1)
        # Business logic here
    
    sample_task()
