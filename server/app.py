"""
server/app.py — FastAPI server for Cloud Incident Response OpenEnv.

Endpoints:
  GET  /          HTML landing page (triggers HF Space "Running" status)
  GET  /health    Health check
  POST /reset     Start new episode
  POST /step      Submit action
  GET  /state     Current episode state
  GET  /tasks     All tasks with schemas
  GET  /grader    Score current episode
  POST /baseline  Run inference.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from server.models import Action
from server.environment import IncidentEnvironment
from tasks import list_tasks, ALL_TASKS

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = FastAPI(
    title="Cloud Incident Response — OpenEnv",
    version="0.1.0",
    description=(
        "OpenEnv environment for training AI agents on cloud SRE incident response. "
        "Covers cascading failures, OOM kills, CDN storms, and network partitions."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

env = IncidentEnvironment()


# ── Landing page (required for HF Space Running status) ─────────────────────

@app.get("/", response_class=HTMLResponse)
def root():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cloud Incident Response — OpenEnv</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 680px;
           margin: 60px auto; padding: 0 20px; color: #1a1a1a; }
    h1   { font-size: 1.6rem; margin-bottom: 4px; }
    .tag { display:inline-block; background:#e8f4fd; color:#0066cc;
           padding:2px 8px; border-radius:4px; font-size:.8rem;
           margin-right:4px; margin-bottom:8px; }
    .status { color: #16a34a; font-weight: 600; }
    table  { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th, td { text-align: left; padding: 8px 12px;
             border-bottom: 1px solid #e5e7eb; font-size: .9rem; }
    th     { background: #f9fafb; font-weight: 600; }
    a      { color: #0066cc; }
    code   { background: #f3f4f6; padding: 1px 5px; border-radius: 3px;
             font-size: .85rem; }
  </style>
</head>
<body>
  <h1>&#x1F6A8; Cloud Incident Response &mdash; OpenEnv</h1>
  <div>
    <span class="tag">openenv</span><span class="tag">sre</span>
    <span class="tag">cloud</span><span class="tag">real-world</span>
    <span class="tag">agentic</span>
  </div>
  <p>Status: <span class="status">&#x2713; Running</span></p>
  <p>
    OpenEnv environment for training and evaluating AI agents on
    cloud SRE incident response. Covers cross-service cascading failures,
    OOM kills, CDN cache storms, and BGP network partitions.
  </p>
  <table>
    <tr><th>Task</th><th>Difficulty</th><th>Max Steps</th></tr>
    <tr><td><code>alert_classification</code></td><td>Easy</td><td>3</td></tr>
    <tr><td><code>root_cause_analysis</code></td><td>Medium</td><td>10</td></tr>
    <tr><td><code>remediation_planning</code></td><td>Hard</td><td>15</td></tr>
  </table>
  <p>
    <a href="/docs">&#x1F4D6; API Docs (Swagger)</a> &nbsp;&middot;&nbsp;
    <a href="/tasks">&#x1F4CB; Tasks</a> &nbsp;&middot;&nbsp;
    <a href="/health">&#x2764; Health</a>
  </p>
</body>
</html>"""


# ── Core endpoints ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


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
    """Submit one action. Returns observation, reward, done, info."""
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
                {"action_type": "query_logs",
                 "parameters": {"service": "string"}},
                {"action_type": "check_metrics",
                 "parameters": {"service": "string"}},
                {"action_type": "check_dependencies",
                 "parameters": {"service": "string"}},
                {"action_type": "check_recent_deploys",
                 "parameters": {"service": "string"}},
                {"action_type": "check_service_status",
                 "parameters": {"service": "string"}},
            ],
            "remediation": [
                {"action_type": "restart_service",
                 "parameters": {"service": "string"}},
                {"action_type": "rollback_deploy",
                 "parameters": {"service": "string",
                                "target_version": "string"}},
                {"action_type": "scale_service",
                 "parameters": {"service": "string", "replicas": "int"}},
                {"action_type": "disable_feature_flag",
                 "parameters": {"flag": "string"}},
                {"action_type": "clear_cache",
                 "parameters": {"service": "string"}},
                {"action_type": "execute_runbook_step",
                 "parameters": {"runbook_action": "string",
                                "target": "string"}},
            ],
            "submission": [
                {"action_type": "submit_severity",
                 "parameters": {"severity": "P1|P2|P3|P4",
                                "service": "string"}},
                {"action_type": "submit_root_cause",
                 "parameters": {"service": "string",
                                "failure_mode": "string"}},
                {"action_type": "submit_resolution",
                 "parameters": {"summary": "string"}},
            ],
        },
    }


@app.get("/grader")
def grader():
    """Score the current episode. Returns total in [0.0, 1.0]."""
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
            status_code=500, detail="inference.py not found in project root"
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
    last = lines[-1] if lines else ""
    try:
        return json.loads(last)
    except Exception:
        return {"raw_output": result.stdout[-3000:]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)
