"""
inference.py — Cloud Incident Response OpenEnv baseline inference script.

Required env vars:
    API_BASE_URL    OpenAI-compatible LLM endpoint
    MODEL_NAME      Model identifier
    HF_TOKEN        API key (Hugging Face token or any OpenAI-compatible key)

Also accepts OPENAI_API_KEY as fallback for HF_TOKEN.

Runs the agent against all 3 tasks x 2 scenarios = 6 episodes.
Final stdout line is valid JSON — required by hackathon validator.

Usage:
    export API_BASE_URL="https://api-inference.huggingface.co/v1"
    export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
    export HF_TOKEN="hf_your_token_here"
    python inference.py
"""

from __future__ import annotations

import json
import os
import sys

import requests
from openai import OpenAI

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Config — accepts both HF_TOKEN and OPENAI_API_KEY ────────────────────────
API_BASE_URL = os.environ.get(
    "API_BASE_URL", "https://api-inference.huggingface.co/v1"
)
MODEL_NAME = os.environ.get(
    "MODEL_NAME", "meta-llama/Llama-3.1-8B-Instruct"
)
HF_TOKEN = (
    os.environ.get("HF_TOKEN")
    or os.environ.get("OPENAI_API_KEY")
    or ""
)
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:7860")

if not HF_TOKEN:
    print(
        "[WARN] Neither HF_TOKEN nor OPENAI_API_KEY is set — "
        "LLM calls will fail.",
        file=sys.stderr,
    )

client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) \
responding to a live production cloud incident.

You receive the incident observation as JSON. \
Respond with ONLY a single valid JSON action — no markdown, no explanation.

Available action_types:

Diagnostic (gather evidence):
  {"action_type": "query_logs",           "parameters": {"service": "<name>"}}
  {"action_type": "check_metrics",        "parameters": {"service": "<name>"}}
  {"action_type": "check_dependencies",   "parameters": {"service": "<name>"}}
  {"action_type": "check_recent_deploys", "parameters": {"service": "<name>"}}
  {"action_type": "check_service_status", "parameters": {"service": "<name>"}}

Remediation (fix the incident):
  {"action_type": "restart_service",      "parameters": {"service": "<name>"}}
  {"action_type": "rollback_deploy",      "parameters": {"service": "<name>", "target_version": "previous"}}
  {"action_type": "scale_service",        "parameters": {"service": "<name>", "replicas": 5}}
  {"action_type": "disable_feature_flag", "parameters": {"flag": "<flag_name>"}}
  {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "<action>"}}

Submission (ends the episode — pick ONE matching the task):
  {"action_type": "submit_severity",   "parameters": {"severity": "P1|P2|P3|P4", "service": "<root_cause>"}}
  {"action_type": "submit_root_cause", "parameters": {"service": "<root_cause>", "failure_mode": "<description>"}}
  {"action_type": "submit_resolution", "parameters": {"summary": "<detailed description of what happened and what you did>"}}

Strategy:
- alert_classification (3 steps max): Query 1-2 key services, then submit_severity.
- root_cause_analysis (10 steps max): Trace the failure chain, identify root service, submit_root_cause.
- remediation_planning (15 steps max): Diagnose, fix the root cause with remediation actions, submit_resolution.

Output ONLY the JSON object. Nothing else."""


def _fmt(obs: dict) -> str:
    parts = [
        f"TASK: {obs.get('task_id')} | "
        f"Step {obs.get('step_count')}/{obs.get('max_steps')}",
        f"INCIDENT: {obs.get('incident_summary', '')}",
    ]
    if obs.get("alert"):
        parts.append("ALERT:\n" + json.dumps(obs["alert"], indent=2))
    if obs.get("available_actions"):
        parts.append(f"AVAILABLE ACTIONS: {obs['available_actions']}")
    if obs.get("queried_data"):
        parts.append("DATA GATHERED:\n" + json.dumps(obs["queried_data"], indent=2))
    parts.append(f"CUMULATIVE REWARD: {obs.get('cumulative_reward', 0.0)}")
    parts.append(f"FEEDBACK: {obs.get('feedback', '')}")
    return "\n\n".join(parts)


def _parse(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            l for l in text.splitlines() if not l.startswith("```")
        ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}") + 1
        if s != -1 and e > s:
            return json.loads(text[s:e])
        raise


def _fallback(task_id: str) -> dict:
    """Safe fallback action when LLM output can't be parsed."""
    if task_id == "alert_classification":
        return {"action_type": "submit_severity",
                "parameters": {"severity": "P2", "service": "unknown"}}
    if task_id == "root_cause_analysis":
        return {"action_type": "submit_root_cause",
                "parameters": {"service": "unknown", "failure_mode": "unknown"}}
    return {"action_type": "submit_resolution",
            "parameters": {"summary": "Unable to determine root cause."}}


def _run_episode(task_id: str, scenario_index: int) -> float:
    r = requests.post(
        f"{ENV_BASE_URL}/reset",
        params={"task_id": task_id, "scenario_index": scenario_index},
        timeout=30,
    )
    r.raise_for_status()
    obs = r.json()
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for _ in range(obs.get("max_steps", 10)):
        messages.append({"role": "user", "content": _fmt(obs)})
        try:
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.0,
                max_tokens=256,
            )
            raw = resp.choices[0].message.content
        except Exception as e:
            print(f"  [WARN] LLM call failed: {e}", file=sys.stderr)
            raw = json.dumps(_fallback(task_id))

        messages.append({"role": "assistant", "content": raw})

        try:
            action = _parse(raw)
        except Exception as e:
            print(f"  [WARN] parse failed: {e}", file=sys.stderr)
            action = _fallback(task_id)

        sr = requests.post(
            f"{ENV_BASE_URL}/step",
            json=action,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        sr.raise_for_status()
        result = sr.json()
        obs = result["observation"]
        if result.get("done"):
            break

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

    print(f"{'Task':<32} {'S':>2}  {'Score':>7}")
    print("-" * 46)

    for task_id, scenario_index in runs:
        try:
            score = _run_episode(task_id, scenario_index)
        except Exception as e:
            print(f"  [ERROR] {task_id} s{scenario_index}: {e}",
                  file=sys.stderr)
            score = 0.0

        label = f"{task_id} [s{scenario_index}]"
        print(f"{label:<32} {scenario_index:>2}  {score:>7.4f}")
        results.setdefault(task_id, []).append(score)

    print("-" * 46)
    summary = {
        t: round(sum(v) / len(v), 4)
        for t, v in results.items()
    }
    summary["overall"] = round(
        sum(summary.values()) / len(summary), 4
    )

    print("\nBaseline Summary:")
    for k, v in summary.items():
        print(f"  {k:<32}: {v:.4f}")

    # Final line MUST be valid JSON — parsed by /baseline endpoint
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
