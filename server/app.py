"""
server/app.py — FastAPI server for Cloud Incident Response OpenEnv.

Endpoints:
  GET  /          JSON health/status (triggers HF Space "Running" badge)
  GET  /health    Lightweight health check
  POST /reset     Start new episode
  POST /step      Submit action
  GET  /state     Current episode state
  GET  /tasks     All tasks with action schemas
  GET  /grader    Score current episode
  POST /baseline  Run inference.py end-to-end, return score summary
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

# Ensure project root is on sys.path regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from server.models import Action
from server.environment import IncidentEnvironment
from tasks import list_tasks, ALL_TASKS

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Global env instance ──────────────────────────────────────────────────────
_env: IncidentEnvironment | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise heavy objects after the server is already accepting requests."""
    global _env
    _env = IncidentEnvironment()
    yield


def _get_env() -> IncidentEnvironment:
    if _env is None:
        raise HTTPException(
            status_code=503,
            detail="Environment initialising — retry in a moment",
        )
    return _env


app = FastAPI(
    title="Cloud Incident Response — OpenEnv",
    version="0.1.0",
    description=(
        "OpenEnv environment for training AI agents on cloud SRE incident response. "
        "Covers cascading failures, OOM kills, CDN storms, and network partitions."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Root — plain JSON so HF Space flips badge to Running ─────────────────────

@app.get("/")
def root():
    return {
        "status":      "running",
        "name":        "cloud-incident-response",
        "version":     "0.1.0",
        "description": "OpenEnv environment for cloud SRE incident response",
        "tasks":       ["alert_classification", "root_cause_analysis", "remediation_planning"],
        "docs":        "/docs",
        "health":      "/health",
    }


# ── Core endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/reset")
def reset(
    task_id:        str = Query(default="alert_classification"),
    scenario_index: int = Query(default=0),
):
    """Start a new episode. Returns the initial observation."""
    env = _get_env()
    try:
        obs = env.reset(task_id=task_id, scenario_index=scenario_index)
        return obs.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/step")
def step(action: Action):
    """Submit one action. Returns observation, reward, done, info."""
    env = _get_env()
    try:
        obs, reward, done, info = env.step(action)
        return {
            "observation": obs.model_dump(),
            "reward":      reward.model_dump(),
            "done":        done,
            "info":        info,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state")
def state():
    """Return the full current episode state."""
    env = _get_env()
    try:
        return env.state().model_dump()
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tasks")
def tasks():
    """Return all tasks with descriptions and action schemas."""
    return {
        "tasks": list_tasks(),
        "total": len(ALL_TASKS),
        "action_schema": {
            "diagnostic": [
                {"action_type": "query_logs",           "parameters": {"service": "string"}},
                {"action_type": "check_metrics",        "parameters": {"service": "string"}},
                {"action_type": "check_dependencies",   "parameters": {"service": "string"}},
                {"action_type": "check_recent_deploys", "parameters": {"service": "string"}},
                {"action_type": "check_service_status", "parameters": {"service": "string"}},
            ],
            "remediation": [
                {"action_type": "restart_service",      "parameters": {"service": "string"}},
                {"action_type": "rollback_deploy",      "parameters": {"service": "string", "target_version": "string"}},
                {"action_type": "scale_service",        "parameters": {"service": "string", "replicas": "int"}},
                {"action_type": "disable_feature_flag", "parameters": {"flag": "string"}},
                {"action_type": "clear_cache",          "parameters": {"service": "string"}},
                {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "string", "target": "string"}},
            ],
            "submission": [
                {"action_type": "submit_severity",   "parameters": {"severity": "P1|P2|P3|P4", "service": "string"}},
                {"action_type": "submit_root_cause", "parameters": {"service": "string", "failure_mode": "string"}},
                {"action_type": "submit_resolution", "parameters": {"summary": "string"}},
            ],
        },
    }


@app.get("/grader")
def grader():
    """Score the current episode. Returns total in [0.0, 1.0]."""
    env = _get_env()
    try:
        s = env.state()
        from graders import grade
        result = grade(s.task_id, s.model_dump(), env._scenario)
        return {
            "total":       result["total"],
            "breakdown":   result["breakdown"],
            "feedback":    result["feedback"],
            "task_id":     s.task_id,
            "scenario_id": s.scenario_id,
            "steps_used":  s.step_count,
            "done":        s.done,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/baseline")
def baseline():
    """Run inference.py and return the JSON score summary."""
    script = os.path.join(_ROOT, "inference.py")
    if not os.path.exists(script):
        raise HTTPException(
            status_code=500,
            detail="inference.py not found in project root",
        )
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            timeout=1200,
            cwd=_ROOT,
            env={**os.environ, "ENV_BASE_URL": "http://localhost:7860"},
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="inference.py timed out (>20 min)")

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr[-2000:])

    lines = result.stdout.strip().splitlines()
    last  = lines[-1] if lines else ""
    try:
        return json.loads(last)
    except Exception:
        return {"raw_output": result.stdout[-3000:]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)