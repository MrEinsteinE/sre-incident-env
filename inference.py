"""
inference.py — Cloud Incident Response OpenEnv baseline inference script.

The LLM reasons from evidence. Fallback is a dumb safety net that scores low.
Override only blocks clearly invalid actions (wrong task submission, bad params).
"""

from __future__ import annotations

import json
import os
import sys

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Config ──────────────────────────────────────────────────────────────────
API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.groq.com/openai/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "llama-3.1-8b-instant")
HF_TOKEN     = os.environ.get("HF_TOKEN") or os.environ.get("OPENAI_API_KEY") or ""
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:7860")

if not HF_TOKEN:
    print("[WARN] No API key set — LLM calls will fail.", file=sys.stderr)

_session = requests.Session()

# Lazy-init OpenAI client to avoid import-time httpx errors
_client = None


def _get_client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)
    return _client


# ── Which submission action belongs to which task ───────────────────────────
_TASK_SUBMIT = {
    "alert_classification":  "submit_severity",
    "root_cause_analysis":   "submit_root_cause",
    "remediation_planning":  "submit_resolution",
}

_DIAG_TYPES = frozenset({
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
})

_SUBMIT_TYPES = frozenset({
    "submit_severity", "submit_root_cause", "submit_resolution",
})

_REM_TYPES = frozenset({
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
})

_ALL_VALID = _DIAG_TYPES | _SUBMIT_TYPES | _REM_TYPES


# ── System prompt — general SRE strategy, NO scenario answers ───────────────
SYSTEM_PROMPT = """\
You are an expert Site Reliability Engineer responding to a production incident.
Reply with exactly ONE JSON action object. No markdown, no explanation, no extra text.

VALID ACTIONS:
{"action_type":"query_logs","parameters":{"service":"<name>"}}
{"action_type":"check_metrics","parameters":{"service":"<name>"}}
{"action_type":"check_dependencies","parameters":{"service":"<name>"}}
{"action_type":"check_recent_deploys","parameters":{"service":"<name>"}}
{"action_type":"check_service_status","parameters":{"service":"<name>"}}
{"action_type":"restart_service","parameters":{"service":"<name>"}}
{"action_type":"rollback_deploy","parameters":{"service":"<name>","target_version":"previous"}}
{"action_type":"disable_feature_flag","parameters":{"flag":"<flag_name>"}}
{"action_type":"execute_runbook_step","parameters":{"runbook_action":"<action>"}}
{"action_type":"submit_severity","parameters":{"severity":"P1|P2|P3|P4","service":"<name>"}}
{"action_type":"submit_root_cause","parameters":{"service":"<name>","failure_mode":"<description>"}}
{"action_type":"submit_resolution","parameters":{"summary":"<3+ sentence summary>"}}

RULES:
- Service names MUST exactly match the KNOWN_SERVICES list in the observation.
- P1 = complete outage OR revenue > $1,000/min.  P2 = major degradation.
  P3 = minor issue.  P4 = informational.
- Root cause = the upstream service that TRIGGERED the cascade. This is often
  NOT listed in the alert's affected_services. Investigate services not in the
  alert first.
- submit_resolution summary must be 3+ sentences: (1) what failed and why,
  (2) actions you took to fix it, (3) current recovery status.
- Submit as soon as evidence is clear — do NOT waste steps querying more.

TASK-SPECIFIC STRATEGY:

alert_classification (max 3 steps):
  Query 1-2 affected services for evidence, then submit_severity.

root_cause_analysis (max 10 steps):
  Investigate services NOT in the alert first (check logs + recent deploys).
  Look for: OOM kills, BGP withdrawals, config changes, unbounded queries.
  Submit submit_root_cause with the triggering service and failure mode.

remediation_planning (max 15 steps):
  1. Query logs to confirm root cause.
  2. Execute fixes: disable bad jobs, restart crashed services, rollback configs,
     run runbook steps.
  3. Submit submit_resolution with a detailed 3-sentence summary.

CRITICAL: Each task has ONE correct submission action:
  alert_classification  -> submit_severity
  root_cause_analysis   -> submit_root_cause
  remediation_planning  -> submit_resolution
Do NOT use the wrong submission type for the task."""


# ── Helpers ─────────────────────────────────────────────────────────────────
def _queried_svcs(queried_data: dict) -> set[str]:
    return {
        svc
        for at, svcs in queried_data.items()
        if at in _DIAG_TYPES and isinstance(svcs, dict)
        for svc in svcs
    }


def _extract_signals(queried_data: dict) -> list[str]:
    """Surface key patterns from queried data — shown to LLM."""
    seen: set[str] = set()
    signals: list[str] = []

    def _add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            signals.append(msg)

    for action_type, services in queried_data.items():
        if not isinstance(services, dict):
            continue
        for svc, data in services.items():
            t = str(data).lower()
            if "out of memory" in t or "oom" in t:
                _add(f"OOM detected in {svc}")
            if "bgp" in t and ("withdrawal" in t or "withdrawn" in t):
                _add(f"BGP route issue in {svc}")
            if "pool" in t and ("exhaust" in t or "too many clients" in t):
                _add(f"Connection pool issue in {svc}")
            if "cache" in t and ("purge" in t or "invalidat" in t):
                _add(f"Cache purge in {svc}")
            if "unbounded" in t or "no limit" in t:
                _add(f"Unbounded query in {svc}")
            if action_type == "check_recent_deploys" and any(
                x in t for x in ("ago", "change", "update", "added")
            ):
                snippet = str(data)[:120].replace("\n", " ")
                _add(f"Recent change in {svc}: {snippet}")
    return signals


# ── Message builders ────────────────────────────────────────────────────────
def _first_obs_msg(obs: dict) -> str:
    alert    = obs.get("alert", {})
    known    = obs.get("known_services", [])
    affected = alert.get("affected_services", [])
    task_id  = obs.get("task_id", "")
    non_aff  = [s for s in known if s not in affected]

    lines = [
        "=== NEW INCIDENT ===",
        f"Task: {task_id}  |  Max steps: {obs.get('max_steps')}",
        f"Scenario: {obs.get('scenario_id', '')}",
        f"INCIDENT: {obs.get('incident_summary', '')}",
    ]

    if alert:
        lines.append("ALERT DETAILS:")
        if alert.get("title"):
            lines.append(f"  Title: {alert['title']}")
        if affected:
            lines.append(f"  Directly affected services: {', '.join(affected)}")
        for s in alert.get("symptoms", []):
            lines.append(f"  - {s}")
        for k in ("error_rate", "duration_minutes", "revenue_impact_per_min"):
            if alert.get(k) is not None:
                lines.append(f"  {k}: {alert[k]}")

    lines.append(f"KNOWN_SERVICES (use these EXACT names): {json.dumps(known)}")

    if non_aff and task_id in ("root_cause_analysis", "remediation_planning"):
        lines.append(
            f"  *** These services are NOT in the alert — investigate them "
            f"for possible root cause: {json.dumps(non_aff)} ***"
        )

    lines.append(f"AVAILABLE ACTIONS: {obs.get('available_actions', [])}")
    lines.append(f"REQUIRED SUBMISSION: {_TASK_SUBMIT.get(task_id, 'unknown')}")
    lines.append("")
    lines.append("Respond with your first action (JSON only, no markdown):")
    return "\n".join(lines)


def _step_msg(obs: dict, prev_queried: dict) -> str:
    step      = obs.get("step_count", 0)
    max_steps = obs.get("max_steps", 10)
    left      = max_steps - step
    queried   = obs.get("queried_data", {})
    task_id   = obs.get("task_id", "")

    lines = [
        f"Step {step}/{max_steps} ({left} remaining) | "
        f"reward={obs.get('cumulative_reward', 0.0):.3f} | "
        f"feedback: {obs.get('feedback', '')}",
    ]

    # Show new data received
    new_data = []
    for action_type, services in queried.items():
        prev = prev_queried.get(action_type, {})
        if isinstance(services, dict):
            for svc, data in services.items():
                if svc not in prev:
                    d = str(data)
                    if len(d) > 500:
                        d = d[:500] + "..."
                    new_data.append(f"  [{action_type}][{svc}]: {d}")
    if new_data:
        lines.append("NEW DATA RECEIVED:")
        lines.extend(new_data)

    # Show extracted signals
    signals = _extract_signals(queried)
    if signals:
        lines.append("KEY SIGNALS DETECTED:")
        for sig in signals:
            lines.append(f"  *** {sig} ***")

    # Urgency reminders
    if left <= 3:
        lines.append(
            f"*** {left} steps remaining — submit "
            f"{_TASK_SUBMIT.get(task_id, 'your answer')} soon ***"
        )
    if left <= 1:
        lines.append(
            f"!!! LAST STEP — YOU MUST {_TASK_SUBMIT.get(task_id, 'SUBMIT')} NOW !!!"
        )

    lines.append("Next action (JSON only, no markdown):")
    return "\n".join(lines)


# ── Parse LLM output ───────────────────────────────────────────────────────
def _parse(text: str) -> dict:
    text = text.strip()
    # Strip markdown code fences
    if text.startswith("`"):
        text = "\n".join(
            ln for ln in text.splitlines() if not ln.startswith("`")
        ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s = text.find("{")
        e = text.rfind("}") + 1
        if s != -1 and e > s:
            return json.loads(text[s:e])
        raise


# ── Fallback — generic, no scenario knowledge ──────────────────────────────
def _fallback_submit(task_id: str, obs: dict) -> dict:
    """Minimal correct-type submission. Will score low but won't crash."""
    alert = obs.get("alert", {})
    known = obs.get("known_services", [])

    if task_id == "alert_classification":
        rev = alert.get("revenue_impact_per_min", 0) or 0
        err = alert.get("error_rate", 0) or 0
        sev = "P1" if (rev > 1000 or err > 0.9) else (
              "P2" if (rev > 100 or err > 0.3) else "P3")
        svc = (alert.get("affected_services") or known or ["unknown"])[0]
        return {
            "action_type": "submit_severity",
            "parameters": {"severity": sev, "service": svc},
        }

    if task_id == "root_cause_analysis":
        svc = known[0] if known else "unknown"
        return {
            "action_type": "submit_root_cause",
            "parameters": {
                "service": svc,
                "failure_mode": "service failure causing downstream cascade",
            },
        }

    # remediation_planning
    return {
        "action_type": "submit_resolution",
        "parameters": {
            "summary": (
                "The incident was investigated through log and metric analysis "
                "across affected services. Remediation actions were applied to "
                "restore service health. Systems are being monitored for full "
                "recovery confirmation."
            ),
        },
    }


def _smart_fallback(
    task_id: str, obs: dict, step: int, max_steps: int
) -> dict:
    """Generic fallback — queries unvisited services, then submits."""
    known   = obs.get("known_services", [])
    queried = obs.get("queried_data", {})
    left    = max_steps - step
    q_svcs  = _queried_svcs(queried)

    # Must submit on final step
    if left <= 1:
        return _fallback_submit(task_id, obs)

    # Alert classification — submit after any query
    if task_id == "alert_classification" and q_svcs:
        return _fallback_submit(task_id, obs)

    # Query next un-queried service
    for svc in known:
        if svc not in q_svcs:
            return {
                "action_type": "query_logs",
                "parameters": {"service": svc},
            }

    # Try check_recent_deploys for unvisited services
    if task_id in ("root_cause_analysis", "remediation_planning"):
        deploy_queried = set(queried.get("check_recent_deploys", {}).keys())
        for svc in known:
            if svc not in deploy_queried:
                return {
                    "action_type": "check_recent_deploys",
                    "parameters": {"service": svc},
                }

    # Everything queried — submit
    return _fallback_submit(task_id, obs)


# ── Override — ONLY blocks clearly invalid actions ──────────────────────────
def _should_override(
    task_id: str, action: dict, obs: dict, step: int, max_steps: int
) -> bool:
    at     = action.get("action_type", "")
    params = action.get("parameters", {})
    left   = max_steps - step
    known  = obs.get("known_services", [])

    # 1. Unknown action type
    if at not in _ALL_VALID:
        return True

    # 2. Must submit on last step
    if left <= 0 and at not in _SUBMIT_TYPES:
        return True

    # 3. WRONG submission type for the task
    #    e.g. submit_severity during remediation_planning
    correct_submit = _TASK_SUBMIT.get(task_id)
    if at in _SUBMIT_TYPES and at != correct_submit:
        return True

    # 4. Service not in known_services (for service-targeted actions)
    svc = (params.get("service") or "").strip()
    if (svc and known
            and at not in ("disable_feature_flag", "execute_runbook_step")
            and svc not in known):
        return True

    # 5. Invalid severity value
    if at == "submit_severity":
        sev = (params.get("severity") or "").upper().strip()
        if sev not in ("P1", "P2", "P3", "P4"):
            return True

    # 6. Empty required fields
    if at == "submit_root_cause":
        svc  = (params.get("service") or "").strip()
        mode = (params.get("failure_mode") or "").strip()
        if not svc or len(mode) < 5:
            return True

    if at == "submit_resolution":
        summary = (params.get("summary") or "").strip()
        if len(summary) < 30:
            return True

    # 7. Remediation action used in alert_classification task
    if task_id == "alert_classification" and at in _REM_TYPES:
        return True

    return False


# ── Episode runner ──────────────────────────────────────────────────────────
def _run_episode(task_id: str, scenario_index: int) -> float:
    r = _session.post(
        f"{ENV_BASE_URL}/reset",
        params={"task_id": task_id, "scenario_index": scenario_index},
        timeout=30,
    )
    r.raise_for_status()
    obs = r.json()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": _first_obs_msg(obs)},
    ]

    prev_queried: dict = {}
    max_steps = obs.get("max_steps", 10)

    for step_i in range(max_steps):
        current_step = step_i + 1

        # ── Call LLM ─────────────────────────────────────────────────────
        try:
            resp = _get_client().chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.0,
                max_tokens=300,
                stream=False,
            )
            raw = resp.choices[0].message.content or ""
        except Exception as e:
            print(f"  [WARN] LLM call failed step {current_step}: {e}",
                  file=sys.stderr)
            raw = ""

        messages.append({"role": "assistant", "content": raw or "{}"})

        # ── Parse ────────────────────────────────────────────────────────
        action = None
        try:
            if raw.strip():
                action = _parse(raw)
        except Exception:
            pass

        # ── Fallback / override ──────────────────────────────────────────
        if action is None:
            action = _smart_fallback(task_id, obs, current_step, max_steps)
            print(f"  [FALLBACK] step {current_step}: "
                  f"{action.get('action_type')}", file=sys.stderr)
        elif _should_override(task_id, action, obs, current_step, max_steps):
            old_at = action.get("action_type")
            action = _smart_fallback(task_id, obs, current_step, max_steps)
            print(f"  [OVERRIDE] step {current_step}: "
                  f"{old_at} -> {action.get('action_type')}",
                  file=sys.stderr)

        # ── Step ─────────────────────────────────────────────────────────
        sr = _session.post(
            f"{ENV_BASE_URL}/step", json=action, timeout=30,
        )
        sr.raise_for_status()
        result  = sr.json()
        new_obs = result["observation"]

        print(
            f"  step {current_step:>2}: {action.get('action_type'):<28} "
            f"reward={result['reward']['value']:+.3f}  "
            f"done={result['done']}",
            file=sys.stderr,
        )

        if result.get("done"):
            break

        step_msg = _step_msg(new_obs, prev_queried)
        messages.append({"role": "user", "content": step_msg})
        prev_queried = {
            k: dict(v)
            for k, v in new_obs.get("queried_data", {}).items()
            if isinstance(v, dict)
        }
        obs = new_obs

        # Keep conversation window manageable
        if len(messages) > 20:
            messages = messages[:2] + messages[-16:]

    g = _session.get(f"{ENV_BASE_URL}/grader", timeout=30)
    g.raise_for_status()
    return g.json().get("total", 0.0)


# ── Entry point ─────────────────────────────────────────────────────────────
def main():
    runs = [
        ("alert_classification",  0),
        ("alert_classification",  1),
        ("root_cause_analysis",   0),
        ("root_cause_analysis",   1),
        ("remediation_planning",  0),
        ("remediation_planning",  1),
    ]

    results: dict[str, list[float]] = {}

    print(f"{'Task':<36} {'S':>2}  {'Score':>7}")
    print("-" * 50)

    for task_id, scenario_index in runs:
        try:
            score = _run_episode(task_id, scenario_index)
        except Exception as e:
            print(f"  [ERROR] {task_id} s{scenario_index}: {e}",
                  file=sys.stderr)
            score = 0.0

        label = f"{task_id} [s{scenario_index}]"
        print(f"{label:<36} {scenario_index:>2}  {score:>7.4f}")
        results.setdefault(task_id, []).append(score)

    print("-" * 50)
    summary = {
        t: round(sum(v) / len(v), 4) for t, v in results.items()
    }
    summary["overall"] = round(sum(summary.values()) / len(summary), 4)

    print("\nScore Summary:")
    for k, v in summary.items():
        print(f"  {k:<36}: {v:.4f}")

    print(json.dumps(summary))


if __name__ == "__main__":
    main()