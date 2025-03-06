# Samsara AI - Enterprise Multi-Agent Framework

[![License](https://img.shields.io/badge/License-Apache_2.0-0078D4)](LICENSE)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/samsara-ai/core/badge)](https://securityscorecards.dev)

## Project Vision
**Samsara AI** redefines enterprise automation through a quantum-ready, zero-trust multi-agent framework that combines:
- **Military-Grade Security** (FIPS 140-3 validated crypto, Zero Trust Architecture)
- **Autonomous Collaboration** (DAG-based workflows with self-healing capabilities)
- **Regulatory Compliance** (GDPR/HIPAA/PCI-DSS built-in controls)

## Key Enterprise Features
| Feature | Technology Stack | Compliance |
|---------|------------------|------------|
| **Agent Swarm Orchestration** | Kubernetes CRD Operators, Istio Service Mesh | SOC2 Type 2 |
| **Federated Learning** | PyTorch Federated, Homomorphic Encryption | NIST SP 800-208 |
| **Observability** | OpenTelemetry, Prometheus, Grafana Loki | ISO 27001 |
| **Post-Quantum Security** | Kyber-1024, Dilithium ML-DSA | FIPS 203 (Draft) |
| **Cost Governance** | ML-driven Resource Optimizer, FinOps API | AWS CCM |

## Architecture Overview
```text
┌──────────────────────────────┐
│   Samsara Control Plane       │
│  ┌─────────────┐ ┌─────────┐ │
│  │ API Gateway │ │ Policy  │ │      Edge
│  │ (FastAPI)   │ │ Engine  │◄├──┐  Deployment
│  └──────┬──────┘ └────┬────┘ │  │  (IoT/5G)
│         ▼              ▼      │  └─────────┐
│  ┌─────────────┐ ┌─────────┐ │             ▼
│  │ Agent       │ │ Key     │ │  ┌─────────────────────┐
│  │ Lifecycle   │ │ Mgmt    │ │  │ Samsara Agent Swarm │
│  │ Manager     │ │ (Vault) │ │  │ ┌───┐ ┌───┐ ┌───┐   │
│  └──────┬──────┘ └────┬────┘ │  │ │Agt│ │Agt│ │Agt│   │
│         ▼              ▼      │  │ └─┬─┘ └─┬─┘ └─┬─┘   │
│  ┌──────────────────────────┐│  │   ▼     ▼     ▼      │
│  │ Distributed Workflow Engine │  │  Auto-Scaling Group  │
│  │ (Apache Airflow + Dask)   ││  └─────────────────────┘
└──────────────────────────────┘
```

## Core Architecture
```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    subgraph ControlPlane
        APIGateway([API Gateway]) --> AuthZ[[RBAC Engine]]
        AuthZ --> Orchestrator{{Orchestrator}}
        Orchestrator -->|Scaling Policies| AutoScaler[Auto-Scaler]
    end

    subgraph DataPlane
        Agents[Agent Swarm] -->|Secure GRPC| FederatedLearning[Federated Learning]
        Agents -->|Encrypted| SharedMemory[(Shared Memory)]
        FederatedLearning --> Aggregator{{Secure Aggregator}}
    end

    ControlPlane -->|mTLS| DataPlane
    APIGateway -->|OAuth2| Observability[[Prometheus, Loki]]
```

## Multi-Agent Collaboration   
```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    participant User as Client
    participant API as API Gateway
    participant Orchestrator
    participant Agent1 as Data Agent
    participant Agent2 as Model Agent
    participant Agent3 as Auditor Agent

    User->>API: POST /task {"type": "risk-analysis"}
    API->>Orchestrator: AuthZ Check
    Orchestrator->>Agent1: Spawn (Bloomberg API)
    Orchestrator->>Agent2: Spawn (PyTorch Model)
    Orchestrator->>Agent3: Spawn (Compliance Auditor)
    
    Agent1->>SharedDB: Write Encrypted Data
    Agent2->>SharedDB: Read Data → Run Simulation
    Agent3->>Agent2: Validate Outputs
    Agent2->>Aggregator: Submit Results (+ DP Noise)
    Aggregator->>API: Final Report
    API->>User: 201 Created + Report URL

```

## Zero-Trust Security
```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    subgraph Identity
        TPM[[TPM 2.0]] -->|Attest| Vault[HashiCorp Vault]
        Vault -->|Dynamic Secrets| API
    end

    subgraph DataFlow
        Agent -->|Kyber-1024| Enclave[Confidential Compute]
        Enclave -->|Homomorphic| Processing[FHE Operations]
    end

    subgraph Policy
        OPA[[Open Policy Agent]] -->|Realtime Checks| Audit[Audit Logs]
        Audit --> Splunk{{Splunk CIM}}
    end

    Identity --> DataFlow
    Policy --> DataFlow

```

## Getting Started

### Prerequisites

- Kubernetes 1.27+ (with cert-manager)
- PostgreSQL 15+ (with pg_partman)
- HashiCorp Vault 1.15+

### Installation
```
# Clone with submodules
git clone --recurse-submodules https://github.com/samsara-ai/core.git

# Initialize infrastructure
terraform -chdir=infrastructure/aws-eks init
terraform apply -var="cluster_name=samsara-prod"

# Deploy Samsara AI
helm install samsara ./charts/samsara \
  --set global.encryptionKey="$(vault read -field=key samsara/encryption)" \
  --set prometheus.retention=1y
```

### Usage Example: Financial Risk Analysis
```
from samsara import agents, workflows

# Create agent swarm
risk_agents = agents.Swarm(
    template="financial-risk:v4.2",
    count=50,
    config={
        "market_data_source": "bloomberg",
        "compliance_profile": "basel-iii"
    }
)

# Define ML workflow
with workflows.DAG("risk-simulation") as dag:
    data_task = dag.add_task(agents.DataCollector(regions=["NA", "EU"]))
    model_task = dag.add_task(agents.RiskModelRunner(ensemble_size=1000))
    audit_task = dag.add_task(agents.ComplianceAuditor())
    
    data_task >> model_task >> audit_task

# Execute with zero-trust verification
results = dag.execute(verification_mode="cryptographic")
```

### Deployment Options

| Environment | Configuration | SLA |
|----------|----------|----------|
| Kubernetes   | docs/deployment/k8s.md   | 99.95%   |
| AWS Outposts   | docs/deployment/aws.md   | 99.9%   |
| Hybrid Edge   | docs/deployment/edge.md   | 99.5%   |
| Docker Compose	   | docs/deployment/docker.md	   | Dev Only   |

### Contribution Guidelines

1. Security First: All PRs must pass:

- Static Application Security Testing (Semgrep)
- Software Bill of Materials (SBOM) audit

2. Compliance Checks:
```
make compliance-check RELEASE_TAG=v2.1.0
```

3. Certified Builds:

- SLSA Level 3 provenance required for production artifacts
- Signed with Cosign and Sigstore
