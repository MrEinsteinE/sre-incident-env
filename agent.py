"""
inference.py — OpenEnv Hackathon baseline inference script.

Required env vars (set in HF Space secrets or .env):
    API_BASE_URL   OpenAI-compatible LLM endpoint
    MODEL_NAME     Model identifier
    HF_TOKEN       API key for the LLM endpoint

Runs the agent against all 3 tasks × 2 scenarios each.
Final stdout line is valid JSON — required by the hackathon validator.

Usage:
    export API_BASE_URL="https://api.groq.com/openai/v1"
    export MODEL_NAME="llama-3.1-8b-instant"
    export HF_TOKEN="gsk_your_key_here"
    python inference.py
"""

from __future__ import annotations

import json
import os
import sys

import requests
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ── Config from env vars (hackathon required names) ──────────────────────────
API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.groq.com/openai/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "llama-3.1-8b-instant")
HF_TOKEN     = os.environ.get("HF_TOKEN",     "")
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:7860")

if not HF_TOKEN:
    print("[WARN] HF_TOKEN is not set — LLM calls will fail.", file=sys.stderr)

client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) responding to a live production incident.

You receive an incident observation as JSON. Respond with ONLY a single valid JSON action object — no markdown, no explanation.

Available action_types and their parameters:
  Diagnostic (gather info):
    {"action_type": "query_logs",           "parameters": {"service": "<name>"}}
    {"action_type": "check_metrics",        "parameters": {"service": "<name>"}}
    {"action_type": "check_dependencies",   "parameters": {"service": "<name>"}}
    {"action_type": "check_recent_deploys", "parameters": {"service": "<name>"}}
    {"action_type": "check_service_status", "parameters": {"service": "<name>"}}

  Remediation (fix the issue):
    {"action_type": "restart_service",      "parameters": {"service": "<name>"}}
    {"action_type": "rollback_deploy",      "parameters": {"service": "<name>", "target_version": "previous"}}
    {"action_type": "scale_service",        "parameters": {"service": "<name>", "replicas": 5}}
    {"action_type": "disable_feature_flag", "parameters": {"flag": "<flag_name>"}}
    {"action_type": "clear_cache",          "parameters": {"service": "<name>"}}
    {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "<action>", "target": "<name>"}}

  Submission (end the episode — choose ONE based on task):
    {"action_type": "submit_severity",   "parameters": {"severity": "P1|P2|P3|P4", "service": "<root_cause_service>"}}
    {"action_type": "submit_root_cause", "parameters": {"service": "<root_cause>", "failure_mode": "<what_went_wrong>"}}
    {"action_type": "submit_resolution", "parameters": {"summary": "<full description of what happened and what you did>"}}

Strategy by task:
  alert_classification (max 3 steps): Query 1-2 services for evidence, then submit_severity.
  root_cause_analysis (max 10 steps): Query logs/metrics/deps for multiple services, trace the failure chain, then submit_root_cause.
  remediation_planning (max 15 steps): Investigate, execute fix actions, then submit_resolution with a detailed summary.

Output ONLY the JSON object. Nothing else."""


def _format_obs(obs: dict) -> str:
    parts = [
        f"TASK: {obs.get('task_id')} | Step {obs.get('step_count')}/{obs.get('max_steps')}",
        f"INCIDENT: {obs.get('incident_summary', '')}",
    ]
    alert = obs.get("alert", {})
    if alert:
        parts.append("ALERT:\n" + json.dumps(alert, indent=2))
    if obs.get("available_actions"):
        parts.append(f"AVAILABLE ACTIONS: {obs['available_actions']}")
    if obs.get("queried_data"):
        parts.append("DATA GATHERED:\n" + json.dumps(obs["queried_data"], indent=2))
    parts.append(f"LAST REWARD: {obs.get('cumulative_reward', 0.0)}")
    parts.append(f"FEEDBACK: {obs.get('feedback', '')}")
    return "\n\n".join(parts)


def _parse_action(text: str) -> dict:
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = [l for l in text.splitlines() if not l.startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(text[start:end])
        raise


def _run_episode(task_id: str, scenario_index: int) -> float:
    r = requests.post(
        f"{ENV_BASE_URL}/reset",
        params={"task_id": task_id, "scenario_index": scenario_index},
        timeout=30,
    )
    r.raise_for_status()
    obs = r.json()

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for _step in range(obs.get("max_steps", 10)):
        messages.append({"role": "user", "content": _format_obs(obs)})

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            temperature=0.0,
            max_tokens=256,
        )
        raw = response.choices[0].message.content
        messages.append({"role": "assistant", "content": raw})

        try:
            action = _parse_action(raw)
        except Exception as e:
            print(f"  [WARN] parse failed at step {_step+1}: {e}", file=sys.stderr)
            # Graceful fallback per task
            if task_id == "alert_classification":
                action = {"action_type": "submit_severity",
                          "parameters": {"severity": "P2", "service": "unknown"}}
            elif task_id == "root_cause_analysis":
                action = {"action_type": "submit_root_cause",
                          "parameters": {"service": "unknown", "failure_mode": "unknown"}}
            else:
                action = {"action_type": "submit_resolution",
                          "parameters": {"summary": "Unable to determine root cause."}}

        step_r = requests.post(
            f"{ENV_BASE_URL}/step",
            json=action,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        step_r.raise_for_status()
        result = step_r.json()
        obs = result["observation"]

        if result.get("done"):
            break

    # Get final grader score
    g = requests.get(f"{ENV_BASE_URL}/grader", timeout=30)
    g.raise_for_status()
    return g.json().get("total", 0.0)


def main():
    runs = [
        ("alert_classification", 0),
        ("alert_classification", 1),
        ("root_cause_analysis",  0),
        ("root_cause_analysis",  1),
        ("remediation_planning", 0),
        ("remediation_planning", 1),
    ]

    results: dict[str, list[float]] = {}

    print(f"{'Task':<30} {'Scenario':>8}  {'Score':>8}")
    print("-" * 52)

    for task_id, scenario_index in runs:
        try:
            score = _run_episode(task_id, scenario_index)
        except Exception as e:
            print(f"  [ERROR] {task_id} s{scenario_index}: {e}", file=sys.stderr)
            score = 0.0

        label = f"{task_id} [s{scenario_index}]"
        print(f"{label:<30} {scenario_index:>8}  {score:>8.4f}")
        results.setdefault(task_id, []).append(score)

    print("-" * 52)
    summary = {task: round(sum(v) / len(v), 4) for task, v in results.items()}
    summary["overall"] = round(sum(summary.values()) / len(summary), 4)

    print("\nBaseline Summary:")
    for k, v in summary.items():
        print(f"  {k:<30}: {v:.4f}")

    # Final line must be valid JSON — parsed by /baseline endpoint
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
