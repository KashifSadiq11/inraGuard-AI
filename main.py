"""
InfraGuard AI — DevOps Intelligence Platform
FastAPI backend with streaming multi-agent analysis.

Endpoints:
  POST /analyze          — stream analysis (SSE)
  POST /analyze/sync     — wait for full result
  GET  /agents           — list available agents
  GET  /health           — health check
  GET  /demo/{scenario}  — run a pre-built demo scenario
"""
import os
import json
from typing import Literal
from dotenv import load_dotenv

from openai import OpenAI
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agents.specialists import get_agent

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="InfraGuard AI",
    description="Multi-agent DevOps intelligence platform powered by Claude",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the frontend UI
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
def root():
    return FileResponse("static/index.html")

def get_client() -> OpenAI:
    from agents.base import make_client
    return make_client()


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

AgentType = Literal["incident", "config", "deployment", "pipeline", "auto"]


class AnalyzeRequest(BaseModel):
    content: str = Field(..., description="Raw input: logs, config file, git diff, or pipeline output")
    agent: AgentType = Field(
        default="auto",
        description=(
            "Specialist agent to use:\n"
            "  auto       — Commander (auto-routes, uses all tools)\n"
            "  incident   — Incident triage & root cause analysis\n"
            "  config     — Security audit for K8s/Terraform/Docker\n"
            "  deployment — Deployment risk assessment\n"
            "  pipeline   — CI/CD pipeline failure diagnosis"
        ),
    )
    context: str | None = Field(
        default=None,
        description="Optional extra context (e.g. 'this is a Kubernetes deployment manifest')",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    import agents.base as _b
    _b.make_client()  # ensures MODEL is updated
    return {"status": "ok", "service": "InfraGuard AI", "model": _b.MODEL}


@app.get("/agents")
def list_agents():
    return {
        "agents": [
            {
                "id": "auto",
                "name": "Commander (Auto)",
                "description": "Orchestrates all specialists. Best for mixed/unknown input.",
                "tools": 8,
            },
            {
                "id": "incident",
                "name": "Incident Triage",
                "description": "Root cause analysis from logs/alerts. Produces severity + runbook.",
                "tools": 2,
            },
            {
                "id": "config",
                "name": "Config Auditor",
                "description": "Security scan for Kubernetes, Terraform, and Docker configs.",
                "tools": 2,
            },
            {
                "id": "deployment",
                "name": "Deployment Risk",
                "description": "Go/no-go assessment from git diffs. Risk score + rollback plan.",
                "tools": 2,
            },
            {
                "id": "pipeline",
                "name": "Pipeline Doctor",
                "description": "Diagnoses CI/CD failures. Exact fix + quick workaround.",
                "tools": 2,
            },
        ]
    }


@app.post("/analyze")
async def analyze_stream(req: AnalyzeRequest):
    """
    Stream analysis as Server-Sent Events.
    Each event is a JSON line: {"type": "text"|"tool_call"|"done", ...}

    Connect with: curl -N -X POST .../analyze -H 'Content-Type: application/json' -d '{...}'
    """
    client = get_client()
    agent = get_agent(req.agent, client)

    user_message = req.content
    if req.context:
        user_message = f"[Context: {req.context}]\n\n{req.content}"

    def event_generator():
        try:
            # Emit metadata first
            import agents.base as _b
            yield f"data: {json.dumps({'type': 'meta', 'agent': agent.name, 'model': _b.MODEL})}\n\n"
            for chunk in agent.run_stream(user_message):
                yield chunk
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/analyze/sync")
async def analyze_sync(req: AnalyzeRequest):
    """
    Non-streaming version — waits for the full response.
    Useful for testing or simple integrations.
    """
    client = get_client()
    agent = get_agent(req.agent, client)

    user_message = req.content
    if req.context:
        user_message = f"[Context: {req.context}]\n\n{req.content}"

    text_chunks = []
    tool_calls = []

    for chunk in agent.run_stream(user_message):
        # chunk is SSE formatted: "data: {...}\n\n"
        if chunk.startswith("data: "):
            try:
                data = json.loads(chunk[6:].strip())
                if data.get("type") == "text":
                    text_chunks.append(data.get("chunk", ""))
                elif data.get("type") == "tool_call" and data.get("status") == "done":
                    tool_calls.append(data.get("tool"))
            except json.JSONDecodeError:
                pass

    return {
        "agent": agent.name,
        "model": __import__("agents.base", fromlist=["MODEL"]).MODEL,
        "analysis": "".join(text_chunks),
        "tools_used": list(set(t for t in tool_calls if t)),
    }


@app.get("/demo/{scenario}")
async def demo(scenario: str):
    """
    Pre-built demo scenarios. Returns streaming analysis.

    Available:
      oom_incident     — OOM kill in production logs
      k8s_audit        — Insecure Kubernetes deployment
      risky_deploy     — High-risk git diff
      pipeline_fail    — Failed CI pipeline
    """
    demos: dict[str, dict] = {
        "oom_incident": {
            "agent": "incident",
            "context": "Production logs from payment-service pod",
            "content": """2024-01-15T03:42:11Z INFO  Starting payment-service v2.3.1
2024-01-15T03:42:12Z INFO  Connected to postgres://db.internal:5432/payments
2024-01-15T03:42:15Z INFO  HTTP server listening on :8080
2024-01-15T03:44:02Z WARN  Memory usage: 85% (1.7GB/2GB)
2024-01-15T03:44:45Z WARN  Memory usage: 92% (1.84GB/2GB)
2024-01-15T03:44:58Z ERROR Connection pool exhausted: postgres://db.internal:5432/payments
2024-01-15T03:45:01Z ERROR Failed to process payment tx_8f3k2: context deadline exceeded
2024-01-15T03:45:01Z ERROR Failed to process payment tx_9a1m5: context deadline exceeded
2024-01-15T03:45:02Z WARN  Memory usage: 98% (1.96GB/2GB)
2024-01-15T03:45:03Z ERROR runtime: out of memory: cannot allocate 524288-byte block
2024-01-15T03:45:03Z FATAL Oom kill signal received, terminating
signal: killed""",
        },
        "k8s_audit": {
            "agent": "config",
            "context": "Kubernetes deployment manifest for api-gateway service",
            "content": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    spec:
      hostNetwork: true
      containers:
      - name: api-gateway
        image: myrepo/api-gateway:latest
        securityContext:
          privileged: true
          runAsUser: 0
          allowPrivilegeEscalation: true
        env:
        - name: DB_PASSWORD
          value: "supersecret123"
        - name: JWT_SECRET
          value: "my-jwt-secret-key"
        resources: {}
        volumeMounts:
        - name: host-vol
          mountPath: /host
      volumes:
      - name: host-vol
        hostPath:
          path: /""",
        },
        "risky_deploy": {
            "agent": "deployment",
            "context": "PR #847 targeting production branch",
            "content": """diff --git a/migrations/20240115_drop_user_columns.sql b/migrations/20240115_drop_user_columns.sql
+++ b/migrations/20240115_drop_user_columns.sql
+ALTER TABLE users DROP COLUMN legacy_token;
+ALTER TABLE users DROP COLUMN old_session_id;
+DROP INDEX idx_users_legacy_token;
diff --git a/config/production.env b/config/production.env
--- a/config/production.env
+++ b/config/production.env
-DATABASE_POOL_SIZE=10
+DATABASE_POOL_SIZE=50
-CACHE_TTL=300
+CACHE_TTL=30
diff --git a/terraform/rds.tf b/terraform/rds.tf
--- a/terraform/rds.tf
+++ b/terraform/rds.tf
-  instance_class = "db.t3.medium"
+  instance_class = "db.r5.xlarge"
+  deletion_protection = false
+  skip_final_snapshot = true
diff --git a/api/routes/users.py b/api/routes/users.py
--- a/api/routes/users.py
+++ b/api/routes/users.py
-@router.get('/api/v1/users/{id}/legacy')
-def get_legacy_user(id: int):
-    pass
-@router.get('/api/v1/users/{id}/sessions')
-def list_user_sessions(id: int):
-    pass""",
        },
        "pipeline_fail": {
            "agent": "pipeline",
            "context": "GitHub Actions workflow for backend service",
            "content": """Run: Build and Test (attempt 1/3)
Step 1/8 : FROM python:3.11-slim
 ---> a9af5b932b63
Step 2/8 : WORKDIR /app
 ---> Using cache
Step 3/8 : COPY requirements.txt .
 ---> Using cache
Step 4/8 : RUN pip install -r requirements.txt
 ---> Running in 3f8a2c1d9e4b
Successfully installed all packages
Step 5/8 : COPY . .
 ---> 8b2e4f1a9c3d
Step 6/8 : RUN python -m pytest tests/ -v --timeout=60
============================= test session starts ==============================
collecting ... collected 47 items
tests/test_auth.py::test_login PASSED
tests/test_auth.py::test_logout PASSED
tests/test_payments.py::test_create_payment PASSED
tests/test_payments.py::test_refund FAILED
FAILED tests/test_payments.py::test_refund - AssertionError: Expected status 200, got 500
tests/test_payments.py::test_idempotency FAILED
FAILED tests/test_payments.py::test_idempotency - requests.exceptions.ConnectionError: Connection refused ('stripe-mock:4010')
tests/test_db.py::test_migration FAILED
FAILED tests/test_db.py::test_migration - sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server: Connection refused
        Is the server running on host "localhost" and accepting
        TCP/IP connections on port 5432?
ERROR: 3 failed, 44 passed in 28.34s
error: Process completed with exit code 1.""",
        },
    }

    if scenario not in demos:
        raise HTTPException(
            status_code=404,
            detail=f"Demo '{scenario}' not found. Available: {', '.join(demos.keys())}",
        )

    demo_data = demos[scenario]
    req = AnalyzeRequest(**demo_data)  # type: ignore

    client = get_client()
    agent = get_agent(req.agent, client)

    user_message = req.content
    if req.context:
        user_message = f"[Context: {req.context}]\n\n{req.content}"

    def event_generator():
        yield f"data: {json.dumps({'type': 'meta', 'scenario': scenario, 'agent': agent.name})}\n\n"
        try:
            for chunk in agent.run_stream(user_message):
                yield chunk
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
