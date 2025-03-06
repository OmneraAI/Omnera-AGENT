"""
samsara_ai/api/app.py

Enterprise REST API Gateway for Samsara AI Agent Management
"""

import os
import time
from typing import Annotated, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, conint
import jwt
from redis import Redis
from prometheus_client import make_asgi_app, Counter, Histogram
import uvicorn
from .database import get_db_session
from ..agents.core import AgentLifecycle

# Configuration Models
class AgentCreateRequest(BaseModel):
    agent_type: str = Field(..., min_length=3, max_length=50, 
                          regex="^[a-zA-Z0-9_-]+$",
                          example="financial_analyzer")
    config_overrides: Optional[dict] = Field(
        default_factory=dict,
        example={"timeout": 30, "priority": "high"}
    )
    owner_email: EmailStr

class TaskExecutionRequest(BaseModel):
    agent_id: str = Field(..., min_length=12, max_length=40,
                         regex="^agent-[a-f0-9]{32}$")
    payload: dict = Field(...,
                         example={"transaction_id": "txn_123", "amount": 45000})
    async_mode: bool = Field(default=True)

# Security & Monitoring
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
redis_conn = Redis(host=os.getenv("REDIS_HOST", "redis-samsara"), 
                  port=6379, db=0, decode_responses=True)

API_REQUESTS = Counter("samsara_api_requests", "API request count", ["endpoint", "method"])
API_LATENCY = Histogram("samsara_api_latency", "API latency distribution", ["endpoint"])

# FastAPI App Configuration
app = FastAPI(
    title="Samsara AI Enterprise API",
    version="2.3.0",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    servers=[{"url": "https://api.samsara.ai", "description": "Production"}]
)

# Prometheus Metrics Endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Security Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting Dependency
def rate_limiter(request: Request) -> bool:
    client_ip = request.client.host
    endpoint = request.url.path
    key = f"rate_limit:{client_ip}:{endpoint}"
    
    current = redis_conn.incr(key)
    if current == 1:
        redis_conn.expire(key, 60)
    
    if current > 100:  # 100 requests/minute
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    return True

# JWT Authentication
async def validate_jwt(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(
            token,
            os.getenv("JWT_SECRET"),
            algorithms=["HS256"],
            audience="samsara_api"
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication"
        )

# API Routes
router = APIRouter(dependencies=[Depends(rate_limiter)])

@router.post("/agents", 
            status_code=status.HTTP_202_ACCEPTED,
            tags=["Agent Management"])
async def create_agent(
    agent_data: AgentCreateRequest,
    db=Depends(get_db_session),
    auth: dict = Depends(validate_jwt)
):
    """
    Provision new AI agent instance with type-specific configuration
    """
    API_REQUESTS.labels(endpoint="/agents", method="POST").inc()
    start_time = time.time()
    
    try:
        lifecycle = AgentLifecycle(db)
        agent_id = lifecycle.spawn_agent(
            agent_type=agent_data.agent_type,
            config_overrides=agent_data.config_overrides,
            owner=agent_data.owner_email
        )
        
        API_LATENCY.labels(endpoint="/agents").observe(time.time() - start_time)
        return {"agent_id": agent_id, "status": "provisioning"}
    
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

@router.post("/tasks",
            tags=["Task Execution"])
async def execute_task(
    task: TaskExecutionRequest,
    db=Depends(get_db_session),
    auth: dict = Depends(validate_jwt)
):
    """
    Execute task through specified agent with async/sync modes
    """
    API_REQUESTS.labels(endpoint="/tasks", method="POST").inc()
    start_time = time.time()
    
    if not auth.get("task_execution"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    # Implementation would route to AgentController.execute_task()
    API_LATENCY.labels(endpoint="/tasks").observe(time.time() - start_time)
    return {"task_id": "task_123", "status": "queued"}

@router.get("/health",
           include_in_schema=False)
async def health_check():
    return {"status": "ok", "version": app.version}

# Error Handling
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
        headers={"X-Error-ID": "ERR123"}
    )

# Finalize App Setup
app.include_router(router, prefix="/api/v1")

# Development Server
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", 8080)),
        ssl_keyfile=os.getenv("SSL_KEY_PATH"),
        ssl_certfile=os.getenv("SSL_CERT_PATH")
    )
