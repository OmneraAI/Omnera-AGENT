"""
samsara_ai/api/routes/agents.py

Enterprise Agent Management API Routes
"""

from datetime import datetime
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, UUID4
import jwt
from redis import Redis
from prometheus_client import Counter
from ..database import DBContext, AgentDBModel
from ..security.rbac import validate_scopes
from ..monitoring import audit_logger

# Pydantic Models
class AgentCreatePayload(BaseModel):
    agent_type: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern="^[a-z0-9_]+$",
        example="fraud_detector"
    )
    environment: str = Field(
        "production",
        enum=["production", "staging", "testing"]
    )
    config_overrides: dict = Field(
        default_factory=dict,
        example={"timeout": 30, "priority": "high"}
    )

class AgentResponse(BaseModel):
    agent_id: UUID4
    status: str = Field(..., enum=["provisioning", "active", "terminated"])
    created_at: datetime
    last_heartbeat: datetime | None
    resource_usage: dict = Field(
        default_factory=dict,
        example={"cpu": "2.1%", "memory": "512MB"}
    )

# Dependencies
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
redis_conn = Redis(host="redis-samsara", port=6379, db=0)

AGENT_OPS_COUNTER = Counter(
    "samsara_agent_operations",
    "Agent lifecycle operations",
    ["operation", "agent_type"]
)

# Router
router = APIRouter(prefix="/agents", tags=["Agent Management"])

@router.post(
    "/",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED
)
async def create_agent(
    payload: AgentCreatePayload,
    db: DBContext,
    token: Annotated[str, Depends(oauth2_scheme)]
):
    """Provision new agent instance with type-specific configuration"""
    try:
        # Authentication & Authorization
        claims = jwt.decode(
            token,
            key=os.getenv("JWT_SECRET"),
            algorithms=["HS256"],
            audience="agent_mgmt"
        )
        validate_scopes(claims["scopes"], required=["agents:create"])
        
        # Idempotency check
        idempotency_key = f"agent_create:{claims['sub']}:{payload.agent_type}"
        if redis_conn.exists(idempotency_key):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate agent creation request"
            )
        redis_conn.setex(idempotency_key, 300, "pending")

        # Database operation
        agent = AgentDBModel(
            agent_type=payload.agent_type,
            environment=payload.environment,
            owner=claims["sub"],
            config=payload.config_overrides
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)

        # Audit logging
        audit_logger.info(
            "AgentCreated",
            agent_id=str(agent.id),
            initiator=claims["sub"],
            agent_type=payload.agent_type
        )
        AGENT_OPS_COUNTER.labels("create", payload.agent_type).inc()

        return {
            "agent_id": agent.id,
            "status": agent.status,
            "created_at": agent.created_at,
            "last_heartbeat": agent.last_heartbeat
        }

    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid credentials"
        )
    finally:
        db.close()

@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID4,
    db: DBContext,
    token: Annotated[str, Depends(oauth2_scheme)]
):
    """Retrieve agent status and metrics"""
    claims = jwt.decode(
        token,
        key=os.getenv("JWT_SECRET"),
        algorithms=["HS256"],
        audience="agent_mgmt"
    )
    
    agent = db.query(AgentDBModel).filter(AgentDBModel.id == agent_id).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    
    # Ownership check
    if agent.owner != claims["sub"] and "agents:read_all" not in claims["scopes"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return agent

@router.put("/{agent_id}/config")
async def update_agent_config(
    agent_id: UUID4,
    config: dict,
    db: DBContext,
    token: Annotated[str, Depends(oauth2_scheme)]
):
    """Update runtime configuration for existing agent"""
    claims = jwt.decode(
        token,
        key=os.getenv("JWT_SECRET"),
        algorithms=["HS256"],
        audience="agent_mgmt"
    )
    validate_scopes(claims["scopes"], required=["agents:update"])
    
    agent = db.query(AgentDBModel).filter(AgentDBModel.id == agent_id).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    
    # Atomic update with versioning
    current_version = agent.config_version
    new_config = agent.config.copy()
    new_config.update(config)
    
    try:
        agent.config = new_config
        agent.config_version += 1
        db.commit()
        
        audit_logger.info(
            "ConfigUpdated",
            agent_id=str(agent_id),
            version=current_version,
            initiator=claims["sub"]
        )
        AGENT_OPS_COUNTER.labels("update", agent.agent_type).inc()
        
        return {"config_version": agent.config_version}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration update failed"
        )

@router.delete("/{agent_id}", status_code=status.HTTP_202_ACCEPTED)
async def terminate_agent(
    agent_id: UUID4,
    db: DBContext,
    token: Annotated[str, Depends(oauth2_scheme)]
):
    """Initiate graceful termination of agent instance"""
    claims = jwt.decode(
        token,
        key=os.getenv("JWT_SECRET"),
        algorithms=["HS256"],
        audience="agent_mgmt"
    )
    validate_scopes(claims["scopes"], required=["agents:delete"])
    
    agent = db.query(AgentDBModel).filter(AgentDBModel.id == agent_id).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    
    # Mark for termination
    agent.status = "terminating"
    db.commit()
    
    audit_logger.info(
        "TerminationStarted",
        agent_id=str(agent_id),
        initiator=claims["sub"]
    )
    AGENT_OPS_COUNTER.labels("terminate", agent.agent_type).inc()
    
    return {"message": "Termination sequence initiated"}
