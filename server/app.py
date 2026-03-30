# SRE Incident Response OpenEnv v0.1.0
"""
server/app.py — FastAPI server exposing the OpenEnv HTTP interface.

Endpoints:
  GET  /health
  GET  /
  POST /reset?task_id=...&scenario_index=...
  POST /step
  GET  /state
  GET  /tasks
  GET  /grader
  POST /baseline
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from server.models import Action
from server.environment import IncidentEnvironment
from tasks import list_tasks, ALL_TASKS

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title="SRE Incident Response — OpenEnv",
    version="0.1.0",
    description="OpenEnv environment for training AI agents on SRE incident response tasks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

env = IncidentEnvironment()


# ── Health / root ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def root():
    return """<!DOCTYPE html>
<html>
<head><title>SRE Incident Response OpenEnv</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:40px auto;padding:20px">
  <h1>&#x1F6A8; SRE Incident Response &mdash; OpenEnv</h1>
  <p>Status: <strong style="color:green">Running &#x2713;</strong></p>
  <p>OpenEnv environment for training AI agents on SRE incident response.</p>
  <ul>
    <li><a href="/health">/health</a> &mdash; Health check</li>
    <li><a href="/tasks">/tasks</a> &mdash; All 3 tasks</li>
    <li><a href="/docs">/docs</a> &mdash; Interactive API docs (Swagger)</li>
  </ul>
  <p><em>Tasks: alert_classification (easy) &rarr; root_cause_analysis (medium) &rarr; remediation_planning (hard)</em></p>
</body>
</html>"""


# ── Core OpenEnv endpoints ───────────────────────────────────────────────────

@app.post("/reset")
def reset(
    task_id: str = Query(default="alert_classification"),
    scenario_index: int = Query(default=0),
):
    """Start a new episode. Returns the initial observation."""
    try:
        obs = env.reset(task_id=task_id, scenario_index=scenario_index)
        return obs.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/step")
def step(action: Action):
    """Submit an action. Returns observation, reward, done, info."""
    try:
        obs, reward, done, info = env.step(action)
        return {
            "observation": obs.model_dump(),
            "reward": reward.model_dump(),
            "done": done,
            "info": info,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state")
def state():
    """Return the full current episode state."""
    try:
        return env.state().model_dump()
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tasks")
def tasks():
    """Return all available tasks with descriptions and action schemas."""
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
                {"action_type": "restart_service",       "parameters": {"service": "string"}},
                {"action_type": "rollback_deploy",       "parameters": {"service": "string", "target_version": "string"}},
                {"action_type": "scale_service",         "parameters": {"service": "string", "replicas": "int"}},
                {"action_type": "disable_feature_flag",  "parameters": {"flag": "string"}},
                {"action_type": "clear_cache",           "parameters": {"service": "string"}},
                {"action_type": "execute_runbook_step",  "parameters": {"runbook_action": "string", "target": "string"}},
            ],
            "submission": [
                {"action_type": "submit_severity",    "parameters": {"severity": "P1|P2|P3|P4", "service": "string"}},
                {"action_type": "submit_root_cause",  "parameters": {"service": "string", "failure_mode": "string"}},
                {"action_type": "submit_resolution",  "parameters": {"summary": "string"}},
            ],
        },
    }


@app.get("/grader")
def grader():
    """Run the grader on the current episode. Returns score in [0.0, 1.0]."""
    try:
        s = env.state()
        from scoring import grade
        result = grade(s.task_id, s.model_dump(), env._scenario)
        return {
            "total": result["total"],
            "breakdown": result["breakdown"],
            "feedback": result["feedback"],
            "task_id": s.task_id,
            "scenario_id": s.scenario_id,
            "steps_used": s.step_count,
            "done": s.done,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/baseline")
def baseline():
    """Run agent.py and return the JSON score summary."""
    script = os.path.join(_PROJECT_ROOT, "agent.py")
    if not os.path.exists(script):
        raise HTTPException(status_code=500, detail="agent.py not found in project root")
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            timeout=1200,
            cwd=_PROJECT_ROOT,
            env={**os.environ, "ENV_BASE_URL": "http://localhost:7860"},
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="agent.py timed out (>20 min)")

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr[-2000:])

    lines = result.stdout.strip().splitlines()
    last_line = lines[-1] if lines else ""
    try:
        return json.loads(last_line)
    except Exception:
        return {"raw_output": result.stdout[-3000:]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)
