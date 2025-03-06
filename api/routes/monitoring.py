"""
samsara_ai/monitoring/core/monitoring.py

Enterprise Monitoring System with Real-time Anomaly Detection
"""

import time
import logging
from datetime import datetime
from typing import Dict, Optional, Callable
from functools import wraps

import numpy as np
from prometheus_client import ( 
    Histogram,
    Counter,
    Gauge,
    start_http_server,
    generate_latest,
    REGISTRY
)
from prometheus_client.core import GaugeMetricFamily
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.metrics import Observation
from scipy.stats import zscore

# Configure Logging
logging.basicConfig(
    format="%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)
logger = logging.getLogger("samsara.monitoring")

# Prometheus Metrics
REQUEST_DURATION = Histogram(
    "samsara_request_duration_seconds",
    "API request duration distribution",
    ["service", "endpoint", "status"],
    buckets=(0.01, 0.1, 0.5, 1, 5, 10, 30)
)

ERROR_COUNTER = Counter(
    "samsara_error_total",
    "Total system errors by type",
    ["error_type", "severity"]
)

SYSTEM_HEALTH = Gauge(
    "samsara_system_health",
    "Overall system health score (0-100)",
    ["component"]
)

# OpenTelemetry Setup
trace.set_tracer_provider(
    TracerProvider(
        resource=Resource.create({"service.name": "samsara-monitoring"})
    )
)
metrics.set_meter_provider(
    MeterProvider(
        resource=Resource.create({"service.name": "samsara-monitoring"})
    )
)

otlp_exporter = OTLPSpanExporter(endpoint="http://otel-collector:4317")
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(otlp_exporter)
)

# Anomaly Detection Config
ANOMALY_CONFIG = {
    "cpu_usage": {"threshold": 0.9, "window": 60},
    "memory_usage": {"threshold": 0.85, "window": 300},
    "latency": {"zscore": 3.0, "window": 60}
}

class AnomalyDetector:
    def __init__(self):
        self.metrics_buffer = {}
        self.alert_callbacks = []
        
    def add_metric(self, name: str, value: float):
        """Buffer metrics for statistical analysis"""
        timestamp = datetime.utcnow().timestamp()
        if name not in self.metrics_buffer:
            self.metrics_buffer[name] = []
        self.metrics_buffer[name].append((timestamp, value))
        self._trim_old_data(name)
        
    def _trim_old_data(self, name: str):
        """Maintain sliding window of metric data"""
        window = ANOMALY_CONFIG.get(name, {}).get("window", 300)
        cutoff = datetime.utcnow().timestamp() - window
        self.metrics_buffer[name] = [
            (t, v) for t, v in self.metrics_buffer[name] 
            if t >= cutoff
        ]
        
    def detect_anomalies(self):
        """Run statistical analysis on buffered metrics"""
        alerts = []
        for metric, config in ANOMALY_CONFIG.items():
            data = [v for _, v in self.metrics_buffer.get(metric, [])]
            
            # Threshold-based detection
            if len(data) > 10 and max(data) > config.get("threshold", 1.0):
                alerts.append({
                    "type": "threshold_breach",
                    "metric": metric,
                    "value": max(data),
                    "threshold": config["threshold"]
                })
                
            # Z-score based detection
            if len(data) > 30:
                z_scores = np.abs(zscore(data[-30:]))
                if any(z_scores > config.get("zscore", 3.0)):
                    alerts.append({
                        "type": "statistical_anomaly",
                        "metric": metric,
                        "zscore": max(z_scores)
                    })
                    
        return alerts

class MonitoringMiddleware:
    def __init__(self, app, service_name: str = "samsara"):
        self.app = app
        self.service_name = service_name
        self.detector = AnomalyDetector()
        
    async def __call__(self, scope, receive, send):
        start_time = time.time()
        status_code = 500
        
        async def wrapped_send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)
            
        try:
            await self.app(scope, receive, wrapped_send)
        except Exception as e:
            ERROR_COUNTER.labels(type(e).__name__, "critical").inc()
            raise
        finally:
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                self.service_name,
                scope["path"],
                status_code // 100
            ).observe(duration)
            
            # Track metrics for anomaly detection
            self.detector.add_metric("latency", duration)
            
            # Trigger anomaly checks
            if random.random() < 0.1:  # Sample 10% of requests
                alerts = self.detector.detect_anomalies()
                for alert in alerts:
                    self._trigger_alert(alert)
                    
    def _trigger_alert(self, alert: Dict):
        """Handle alert escalation and logging"""
        logger.warning(f"Anomaly detected: {alert}")
        for callback in self.alert_callbacks:
            callback(alert)

# Health Check Endpoints
def healthz():
    return {"status": "OK", "timestamp": datetime.utcnow().isoformat()}

def readyz():
    return {
        "dependencies": {
            "redis": _check_redis_connection(),
            "otel": _check_otel_connection()
        }
    }

def _check_redis_connection() -> Dict:
    try:
        # Implement actual connection check
        return {"status": "OK", "latency": 0.5}
    except Exception as e:
        return {"status": "DOWN", "error": str(e)}

def _check_otel_connection() -> Dict:
    try:
        # Implement OTLP exporter check
        return {"status": "OK"}
    except Exception as e:
        return {"status": "DOWN", "error": str(e)}

# Custom Metrics Collection
class ResourceUsageCollector:
    def collect(self):
        """Custom collector for system resource metrics"""
        # Sample data - replace with actual resource monitoring
        yield GaugeMetricFamily(
            "samsara_cpu_usage", 
            "Current CPU utilization", 
            value=0.65
        )
        yield GaugeMetricFamily(
            "samsara_memory_usage_bytes",
            "Memory usage in bytes",
            value=2.5e9
        )

# Initialize Monitoring
def init_monitoring(service_name: str = "samsara"):
    # Start Prometheus endpoint
    start_http_server(9100)
    REGISTRY.register(ResourceUsageCollector())
    
    # Configure OpenTelemetry
    tracer = trace.get_tracer(__name__)
    meter = metrics.get_meter(__name__)
    
    # Create system health metric
    meter.create_observable_gauge(
        name="system.health",
        callbacks=[_observe_system_health],
        description="Overall system health score"
    )
    
    return tracer, meter

def _observe_system_health() -> Observation:
    """Generate synthetic health metric (replace with real checks)"""
    return Observation(85, {"component": "core"})

# Decorator for business metrics
def track_metrics(name: str, labels: Optional[Dict] = None):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                ERROR_COUNTER.labels("none", "info").inc()
                return result
            except Exception as e:
                ERROR_COUNTER.labels(type(e).__name__, "error").inc()
                raise
            finally:
                duration = time.time() - start_time
                REQUEST_DURATION.labels(
                    "custom",
                    name,
                    "200" if not e else "500"
                ).observe(duration)
        return wrapper
    return decorator

# Example Usage
if __name__ == "__main__":
    tracer, meter = init_monitoring()
    
    with tracer.start_as_current_span("monitoring_init"):
        logger.info("Monitoring system initialized")
        SYSTEM_HEALTH.labels("monitoring").set(100)
