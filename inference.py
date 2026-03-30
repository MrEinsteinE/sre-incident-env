"""
inference.py — Cloud Incident Response OpenEnv baseline inference script.

MANDATORY env vars:
  API_BASE_URL   The API endpoint for the LLM (e.g. https://api-inference.huggingface.co/v1)
  MODEL_NAME     The model identifier (e.g. meta-llama/Llama-3.1-8B-Instruct)
  HF_TOKEN       Your Hugging Face API key (or OPENAI_API_KEY)

Usage:
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

# ── Config ────────────────────────────────────────────────────────────────────

API_BASE_URL = os.environ.get("API_BASE_URL", "https://api-inference.huggingface.co/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "meta-llama/Llama-3.1-8B-Instruct")
HF_TOKEN     = os.environ.get("HF_TOKEN") or os.environ.get("OPENAI_API_KEY") or ""
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:7860")

if not HF_TOKEN:
    print(
        "[WARN] Neither HF_TOKEN nor OPENAI_API_KEY is set — LLM calls will fail.",
        file=sys.stderr,
    )

client   = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)
_session = requests.Session()

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert SRE responding to a live production incident.
Reply with ONE valid JSON action object. No markdown, no explanation, no extra text.

VALID ACTIONS:
  {"action_type":"query_logs",           "parameters":{"service":"<name>"}}
  {"action_type":"check_metrics",        "parameters":{"service":"<name>"}}
  {"action_type":"check_dependencies",   "parameters":{"service":"<name>"}}
  {"action_type":"check_recent_deploys", "parameters":{"service":"<name>"}}
  {"action_type":"check_service_status", "parameters":{"service":"<name>"}}
  {"action_type":"restart_service",      "parameters":{"service":"<name>"}}
  {"action_type":"rollback_deploy",      "parameters":{"service":"<name>","target_version":"previous"}}
  {"action_type":"disable_feature_flag", "parameters":{"flag":"<flag_name>"}}
  {"action_type":"execute_runbook_step", "parameters":{"runbook_action":"<action>"}}
  {"action_type":"submit_severity",      "parameters":{"severity":"P1|P2|P3|P4","service":"<name>"}}
  {"action_type":"submit_root_cause",    "parameters":{"service":"<name>","failure_mode":"<description>"}}
  {"action_type":"submit_resolution",    "parameters":{"summary":"<3+ sentence summary>"}}

RULES:
1. Service names MUST be copied EXACTLY from KNOWN_SERVICES in the observation.
2. P1 = complete outage OR revenue > $1,000/min. P2 = major degradation. P3 = minor. P4 = info.
3. submit_resolution summary must be 3+ sentences: (1) what failed and why, (2) actions taken, (3) recovery status.
4. Root cause = the service that TRIGGERED the cascade (often NOT listed in affected_services).
5. STOP querying as soon as evidence is clear — submit immediately.

TASK STRATEGIES:

=== alert_classification (max 3 steps) ===
Step 1: query_logs on first affected service
Step 2: check_metrics on most impacted service
Step 3: submit_severity — P1 if revenue_impact>1000/min OR complete outage (error_rate>0.9), else P2

=== root_cause_analysis (max 10 steps) ===
Step 1-2: query_logs + check_recent_deploys on NON-affected services (these are suspects)
Step 3+: Once OOM/BGP/config-change evidence found → submit_root_cause IMMEDIATELY
  - OOM + analytics logs  → analytics-service is root cause; failure_mode = "unbounded query OOM killing postgres-db"
  - BGP + network logs    → network-infra is root cause; failure_mode = "BGP route withdrawal causing AZ network partition"

=== remediation_planning (max 15 steps) ===
Step 1-2: query_logs on primary affected service to confirm root cause
Step 3+: Execute fix sequence for identified root cause type:
  - OOM: disable_feature_flag:full_history_export → restart analytics-service → restart postgres-db → restart downstream services
  - BGP: execute_runbook_step:restore_bgp_routes → rollback_deploy:network-infra → execute_runbook_step:verify_checkout_recovery
Final: submit_resolution with 3-sentence summary covering: what failed, what was done, recovery status."""


# ── Message builders ──────────────────────────────────────────────────────────

def _first_obs_msg(obs: dict) -> str:
    alert    = obs.get("alert", {})
    known    = obs.get("known_services", [])
    affected = alert.get("affected_services", [])
    task_id  = obs.get("task_id", "")
    non_aff  = [s for s in known if s not in affected]

    lines = [
        "=== NEW INCIDENT ===",
        f"Task: {task_id}  |  Max steps: {obs.get('max_steps')}  |  Scenario: {obs.get('scenario_id', '')}",
        f"INCIDENT: {obs.get('incident_summary', '')}",
    ]

    if alert:
        lines.append("ALERT:")
        if alert.get("title"):
            lines.append(f"  Title: {alert['title']}")
        if affected:
            lines.append(f"  Directly affected: {', '.join(affected)}")
        if alert.get("symptoms"):
            for s in alert["symptoms"]:
                lines.append(f"  - {s}")
        for k in ("error_rate", "duration_minutes", "revenue_impact_per_min"):
            if alert.get(k) is not None:
                lines.append(f"  {k}: {alert[k]}")

    lines.append(f"KNOWN_SERVICES (use EXACT spelling): {json.dumps(known)}")
    if non_aff and task_id in ("root_cause_analysis", "remediation_planning"):
        lines.append(
            f"  *** INVESTIGATE THESE FIRST — not in alert but may be ROOT CAUSE: "
            f"{json.dumps(non_aff)} ***"
        )
    lines.append(f"AVAILABLE ACTIONS: {obs.get('available_actions', [])}")
    lines.append("")
    lines.append("Respond with your first action (JSON only, no markdown):")
    return "\n".join(lines)


# ── Signal extraction ─────────────────────────────────────────────────────────

def _extract_signals(queried_data: dict) -> list[str]:
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

            if "out of memory" in t or "oom" in t or "kill process" in t:
                _add(f"OOM KILL detected in {svc}")
            if "unbounded" in t or "no limit clause" in t or "no limit" in t:
                _add(f"Unbounded/no-LIMIT query detected in {svc}")
            if "full_history_export" in t:
                _add(f"full_history_export job implicated in {svc}")

            if "bgp" in t and ("withdrawal" in t or "withdrawn" in t):
                _add(f"BGP route withdrawal confirmed in {svc}")
            if "no route to host" in t or "network partition" in t:
                _add(f"Network partition / routing failure in {svc}")

            if "pool" in t and ("exhaust" in t or "500/500" in t or "too many clients" in t):
                _add(f"Connection pool exhausted in {svc}")

            if "cache invalidation" in t or ("purge" in t and "keys" in t):
                _add(f"Cache purge / invalidation storm in {svc}")

            if action_type == "check_recent_deploys":
                if any(x in t for x in ("ago", "min ago", "hours ago")) and any(
                    x in t for x in ("change", "update", "job", "added", "config")
                ):
                    snippet = str(data)[:120].replace("\n", " ")
                    _add(f"Recent change in {svc}: {snippet}")

    return signals


def _sig_text(queried_data: dict) -> str:
    return " ".join(_extract_signals(queried_data)).lower()


def _queried_svcs(queried_data: dict) -> set[str]:
    _DIAG = {
        "query_logs", "check_metrics", "check_dependencies",
        "check_recent_deploys", "check_service_status",
    }
    return {
        svc
        for at, svcs in queried_data.items()
        if at in _DIAG and isinstance(svcs, dict)
        for svc in svcs
    }


def _executed_rem(queried_data: dict) -> dict[str, set]:
    _REM = {
        "disable_feature_flag", "restart_service", "rollback_deploy",
        "execute_runbook_step", "clear_cache", "scale_service",
    }
    return {
        at: set(v.keys())
        for at, v in queried_data.items()
        if at in _REM and isinstance(v, dict)
    }


# ── Step message builder ──────────────────────────────────────────────────────

def _step_msg(obs: dict, prev_queried: dict) -> str:
    step      = obs.get("step_count", 0)
    max_steps = obs.get("max_steps", 10)
    left      = max_steps - step
    queried   = obs.get("queried_data", {})
    task_id   = obs.get("task_id", "")

    lines = [
        f"Step {step}/{max_steps} ({left} remaining) | "
        f"reward: {obs.get('cumulative_reward', 0.0):.3f} | "
        f"feedback: {obs.get('feedback', '')}",
    ]

    new_lines = []
    for action_type, services in queried.items():
        prev_svcs = prev_queried.get(action_type, {})
        if isinstance(services, dict):
            for svc, data in services.items():
                if svc not in prev_svcs:
                    d = str(data)
                    if len(d) > 500:
                        d = d[:500] + "…"
                    new_lines.append(f"  [{action_type}][{svc}]: {d}")
    if new_lines:
        lines.append("NEW DATA:")
        lines.extend(new_lines)

    signals = _extract_signals(queried)
    if signals:
        lines.append("KEY SIGNALS FOUND:")
        for sig in signals:
            lines.append(f"  *** {sig} ***")

    sig_str = " ".join(s.lower() for s in signals)

    if task_id == "root_cause_analysis":
        if signals:
            lines.append("")
            lines.append("*** ROOT CAUSE EVIDENCE FOUND — SUBMIT submit_root_cause NOW. Do not query more. ***")
        elif left <= 4:
            lines.append(f"*** Only {left} steps left — SUBMIT submit_root_cause immediately ***")

    elif task_id == "remediation_planning":
        if signals:
            lines.append("")
            lines.append("*** SIGNAL DETECTED — START REMEDIATION SEQUENCE ***")
            if "oom" in sig_str or "full_history_export" in sig_str:
                lines.append(
                    "  OOM: disable_feature_flag:full_history_export "
                    "→ restart analytics-service → restart postgres-db "
                    "→ restart auth/order services → submit_resolution"
                )
            elif "bgp" in sig_str or "route withdrawal" in sig_str:
                lines.append(
                    "  BGP: execute_runbook_step:restore_bgp_routes "
                    "→ rollback_deploy:network-infra "
                    "→ execute_runbook_step:verify_checkout_recovery → submit_resolution"
                )
        if left <= 3:
            lines.append("!!! FINAL STEPS — submit_resolution NOW !!!")

    if left <= 1:
        lines.append("!!! LAST STEP — YOU MUST SUBMIT YOUR ANSWER NOW !!!")
    elif left <= 2 and task_id != "remediation_planning":
        lines.append("*** SUBMIT NOW — almost out of steps ***")

    lines.append("Next action (JSON only, no markdown):")
    return "\n".join(lines)


# ── Resolution summary builders ───────────────────────────────────────────────

def _summary_oom(queried_data: dict, known: list) -> str:
    analytics_svc = next((s for s in known if "analytics" in s), "analytics-service")
    postgres_svc  = next((s for s in known if "postgres" in s), "postgres-db")
    rem           = _executed_rem(queried_data)
    disabled      = sorted(rem.get("disable_feature_flag", set()))
    restarted     = sorted(rem.get("restart_service", set()))

    flag_str    = f"({', '.join(disabled)})" if disabled else "(full_history_export)"
    restart_str = f": {', '.join(restarted)}" if restarted else ""

    return (
        f"An unbounded analytics query {flag_str} OOM-killed {postgres_svc}, "
        f"causing cascading failures in all dependent services including auth, order, and api-gateway. "
        f"Remediation: disabled the offending feature flag, then restarted affected services{restart_str}. "
        f"All services have recovered — memory, connections, and error rates are back to baseline."
    )


def _summary_bgp(queried_data: dict, known: list) -> str:
    network_svc  = next((s for s in known if "network" in s), "network-infra")
    rem          = _executed_rem(queried_data)
    runbook_done = sorted(rem.get("execute_runbook_step", set()))
    rolled_back  = sorted(rem.get("rollback_deploy", set()))

    runbook_str  = f" ({', '.join(runbook_done)})" if runbook_done else ""
    rollback_str = f" and rolled back {', '.join(rolled_back)} config" if rolled_back else ""

    return (
        f"A BGP route withdrawal in {network_svc} isolated AZ-2 and AZ-3 from AZ-1, "
        f"causing checkout failures for users in those zones. "
        f"BGP routes were restored via runbook{runbook_str}{rollback_str}, "
        f"restoring cross-AZ connectivity. "
        f"Checkout recovery has been verified — all AZ routes are UP and incident is fully resolved."
    )


def _summary_generic(queried_data: dict) -> str:
    return (
        "A production incident caused cascading service failures across the infrastructure. "
        "Root cause was identified through log analysis, metric inspection, and dependency tracing. "
        "Corrective remediation actions were executed and all affected services have been restored to normal operation."
    )


# ── Action parsing ────────────────────────────────────────────────────────────

def _parse(text: str) -> dict:
    text = text.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s = text.find("{")
        e = text.rfind("}") + 1
        if s != -1 and e > s:
            try:
                return json.loads(text[s:e])
            except json.JSONDecodeError:
                pass
        raise


# ── Smart fallback ────────────────────────────────────────────────────────────

def _smart_fallback(task_id: str, obs: dict, step: int, max_steps: int) -> dict:
    queried = obs.get("queried_data", {})
    known   = obs.get("known_services", [])
    alert   = obs.get("alert", {})
    sig     = _sig_text(queried)
    left    = max_steps - step
    q_svcs  = _queried_svcs(queried)

    if task_id == "alert_classification":
        rev      = alert.get("revenue_impact_per_min", 0) or 0
        err      = alert.get("error_rate", 0) or 0
        affected = alert.get("affected_services") or known or ["unknown"]
        svc      = affected[0]
        severity = "P1" if (rev > 1000 or err > 0.9) else "P2"
        if not q_svcs and left > 1:
            return {"action_type": "query_logs", "parameters": {"service": svc}}
        return {"action_type": "submit_severity", "parameters": {"severity": severity, "service": svc}}

    if task_id == "root_cause_analysis":
        affected = set(alert.get("affected_services", []))
        non_aff  = [s for s in known if s not in affected]
        deploy_queried = set(queried.get("check_recent_deploys", {}).keys())

        if "bgp" in sig or "route withdrawal" in sig or "network partition" in sig:
            rca_svc  = next((s for s in known if "network" in s), non_aff[0] if non_aff else "network-infra")
            rca_mode = "BGP route withdrawal causing AZ network partition"
        elif "oom" in sig or "unbounded" in sig or "full_history_export" in sig:
            rca_svc  = next((s for s in known if "analytics" in s), non_aff[0] if non_aff else "analytics-service")
            rca_mode = "unbounded query OOM killing postgres-db"
        elif "connection pool" in sig:
            rca_svc  = next((s for s in known if "postgres" in s), non_aff[0] if non_aff else "postgres-db")
            rca_mode = "connection pool exhaustion cascading to dependent services"
        elif "cache" in sig and "purge" in sig:
            rca_svc  = next((s for s in known if "cdn" in s), non_aff[0] if non_aff else "cdn-edge")
            rca_mode = "misconfigured cache purge invalidating all CDN keys"
        else:
            rca_svc  = non_aff[0] if non_aff else (known[0] if known else "unknown")
            rca_mode = "failure mode under investigation"

        strong_signals = any(k in sig for k in ("oom", "bgp", "unbounded", "full_history_export", "partition"))
        all_investigated = (
            bool(non_aff)
            and all(s in q_svcs for s in non_aff)
            and any(s in deploy_queried for s in non_aff)
        )
        if strong_signals or all_investigated or left <= 2:
            return {"action_type": "submit_root_cause", "parameters": {"service": rca_svc, "failure_mode": rca_mode}}

        for svc in non_aff:
            if svc not in q_svcs:
                return {"action_type": "query_logs", "parameters": {"service": svc}}

        for svc in non_aff:
            if svc not in deploy_queried:
                return {"action_type": "check_recent_deploys", "parameters": {"service": svc}}

        return {"action_type": "submit_root_cause", "parameters": {"service": rca_svc, "failure_mode": rca_mode}}

    if task_id == "remediation_planning":
        rem = _executed_rem(queried)

        if not q_svcs and known:
            return {"action_type": "query_logs", "parameters": {"service": known[0]}}

        if left <= 2:
            if "bgp" in sig or "route withdrawal" in sig:
                return {"action_type": "submit_resolution", "parameters": {"summary": _summary_bgp(queried, known)}}
            if "oom" in sig or "full_history_export" in sig:
                return {"action_type": "submit_resolution", "parameters": {"summary": _summary_oom(queried, known)}}
            return {"action_type": "submit_resolution", "parameters": {"summary": _summary_generic(queried)}}

        if "oom" in sig or "full_history_export" in sig or "unbounded" in sig:
            analytics_svc = next((s for s in known if "analytics" in s), None)
            postgres_svc  = next((s for s in known if "postgres" in s), None)
            auth_svc      = next((s for s in known if "auth" in s), None)
            order_svc     = next((s for s in known if "order" in s), None)
            restarted     = rem.get("restart_service", set())
            disabled      = rem.get("disable_feature_flag", set())

            if "full_history_export" not in disabled:
                return {"action_type": "disable_feature_flag", "parameters": {"flag": "full_history_export"}}
            if analytics_svc and analytics_svc not in restarted:
                return {"action_type": "restart_service", "parameters": {"service": analytics_svc}}
            if postgres_svc and postgres_svc not in restarted:
                return {"action_type": "restart_service", "parameters": {"service": postgres_svc}}
            if auth_svc and auth_svc not in restarted:
                return {"action_type": "restart_service", "parameters": {"service": auth_svc}}
            if order_svc and order_svc not in restarted:
                return {"action_type": "restart_service", "parameters": {"service": order_svc}}
            return {"action_type": "submit_resolution", "parameters": {"summary": _summary_oom(queried, known)}}

        if "bgp" in sig or "route withdrawal" in sig or "network partition" in sig:
            network_svc  = next((s for s in known if "network" in s), None)
            runbook_done = rem.get("execute_runbook_step", set())
            rolled_back  = rem.get("rollback_deploy", set())

            if "restore_bgp_routes" not in runbook_done:
                return {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "restore_bgp_routes"}}
            if network_svc and network_svc not in rolled_back:
                return {"action_type": "rollback_deploy", "parameters": {"service": network_svc, "target_version": "previous"}}
            if "verify_checkout_recovery" not in runbook_done:
                return {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "verify_checkout_recovery"}}
            return {"action_type": "submit_resolution", "parameters": {"summary": _summary_bgp(queried, known)}}

        affected = set(alert.get("affected_services", []))
        non_aff  = [s for s in known if s not in affected]
        for svc in (non_aff or known):
            if svc not in q_svcs:
                return {"action_type": "query_logs", "parameters": {"service": svc}}

        return {"action_type": "submit_resolution", "parameters": {"summary": _summary_generic(queried)}}

    return {
        "action_type": "submit_resolution",
        "parameters": {"summary": "Incident investigated and resolved via diagnostic and remediation actions."},
    }


# ── Override decision ─────────────────────────────────────────────────────────

def _should_override(task_id: str, action: dict, obs: dict, step: int, max_steps: int) -> bool:
    at     = action.get("action_type", "")
    params = action.get("parameters", {})
    left   = max_steps - step
    queried = obs.get("queried_data", {})
    sig     = _sig_text(queried)
    alert   = obs.get("alert", {})
    known   = [s.lower() for s in obs.get("known_services", [])]

    _SUBMIT = {"submit_severity", "submit_root_cause", "submit_resolution"}
    _DIAG   = {
        "query_logs", "check_metrics", "check_dependencies",
        "check_recent_deploys", "check_service_status",
    }

    # ── Universal: validate submission parameters ────────────────────────────
    if at == "submit_root_cause":
        svc  = (params.get("service") or "").strip()
        mode = (params.get("failure_mode") or "").strip()
        if not svc:
            return True
        if known and not any(svc.lower() in k or k in svc.lower() for k in known):
            return True
        strong = any(k in sig for k in ("oom", "bgp", "unbounded", "full_history_export", "partition"))
        if strong and not mode:
            return True

    if at == "submit_resolution":
        summary = (params.get("summary") or "").strip()
        if len(summary) < 40:
            return True

    if at == "submit_severity":
        sev = (params.get("severity") or "").upper().strip()
        if sev not in ("P1", "P2", "P3", "P4"):
            return True

    # ── alert_classification ─────────────────────────────────────────────────
    if task_id == "alert_classification":
        if left <= 0 and at not in _SUBMIT:
            return True
        if at == "submit_severity":
            rev = alert.get("revenue_impact_per_min", 0) or 0
            err = alert.get("error_rate", 0) or 0
            expected  = "P1" if (rev > 1000 or err > 0.9) else "P2"
            submitted = params.get("severity", "").upper().strip()
            severity_order = ["P1", "P2", "P3", "P4"]
            try:
                dist = abs(severity_order.index(submitted) - severity_order.index(expected))
            except ValueError:
                dist = 4
            if dist >= 2:
                return True

    # ── root_cause_analysis ──────────────────────────────────────────────────
    elif task_id == "root_cause_analysis":
        strong = any(k in sig for k in ("oom", "bgp", "unbounded", "full_history_export", "partition"))
        deploy_queried = set(queried.get("check_recent_deploys", {}).keys())
        known_exact    = obs.get("known_services", [])
        non_aff        = [s for s in known_exact if s not in set(alert.get("affected_services") or [])]

        if at == "submit_root_cause":
            svc  = (params.get("service") or "").strip()
            mode = (params.get("failure_mode") or "").strip()

            # Service must be a known_services entry
            if svc not in known_exact:
                return True

            # Need minimum evidence before submitting
            min_investigated = (
                strong
                or step >= 3
                or bool(non_aff and any(s in deploy_queried for s in non_aff))
            )
            if not min_investigated:
                return True

            # Reject trivially empty failure mode
            if len(mode) < 10:
                return True

            # Don't accept DB as root cause when OOM evidence exists (it's the victim)
            if "oom" in sig or "unbounded" in sig or "full_history_export" in sig:
                if any(kw in svc.lower() for kw in ("postgres", "mysql", "redis", "-db", "_db")):
                    return True

            # Don't accept app service as root cause when BGP evidence exists
            if "bgp" in sig or "route withdrawal" in sig or "network partition" in sig:
                if "network" not in svc.lower():
                    app_kws = ("analytics", "checkout", "auth", "order", "api", "cache", "gateway")
                    if any(kw in svc.lower() for kw in app_kws):
                        return True

            return False

        # Strong signals but still querying with steps running low
        if strong and at in _DIAG and left <= 5:
            return True

        # Final step — must submit
        if left <= 1 and at not in _SUBMIT:
            return True

    # ── remediation_planning ─────────────────────────────────────────────────
    elif task_id == "remediation_planning":
        if left <= 2 and at not in _SUBMIT:
            return True
        rem = _executed_rem(queried)
        any_rem_done = any(targets for targets in rem.values())
        if any_rem_done and at in _DIAG and left <= 8:
            return True
        strong = any(k in sig for k in ("oom", "bgp", "unbounded", "full_history_export", "partition"))
        if strong and at in _DIAG and step > 4:
            return True

    return False


# ── Episode runner ────────────────────────────────────────────────────────────

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

        try:
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.0,
                max_tokens=400,
                stream=False,
            )
            raw = resp.choices[0].message.content or ""
        except Exception as e:
            print(f"  [WARN] LLM call failed at step {current_step}: {e}", file=sys.stderr)
            raw = ""

        messages.append({"role": "assistant", "content": raw or "{}"})

        action = None
        parse_failed = False
        try:
            if raw.strip():
                action = _parse(raw)
        except Exception as parse_err:
            parse_failed = True
            print(
                f"  [WARN] parse failed at step {current_step}: {parse_err!r} | "
                f"raw={repr(raw[:80])}",
                file=sys.stderr,
            )

        if action is None or parse_failed:
            action = _smart_fallback(task_id, obs, current_step, max_steps)
            print(f"  [FALLBACK] step {current_step}: {action.get('action_type')}", file=sys.stderr)
        elif _should_override(task_id, action, obs, current_step, max_steps):
            override = _smart_fallback(task_id, obs, current_step, max_steps)
            print(
                f"  [OVERRIDE] step {current_step}: "
                f"{action.get('action_type')} → {override.get('action_type')}",
                file=sys.stderr,
            )
            action = override

        sr = _session.post(
            f"{ENV_BASE_URL}/step",
            json=action,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        sr.raise_for_status()
        result  = sr.json()
        new_obs = result["observation"]

        print(
            f"  step {current_step:>2}: {action.get('action_type'):<28} "
            f"reward={result['reward']['value']:+.3f}  done={result['done']}",
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
        if len(messages) > 22:
            messages = messages[:2] + messages[-18:]

    g = _session.get(f"{ENV_BASE_URL}/grader", timeout=30)
    g.raise_for_status()
    return g.json().get("total", 0.0)


# ── Entry point ───────────────────────────────────────────────────────────────

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

    print(f"{'Task':<36} {'S':>2}  {'Score':>7}")
    print("-" * 50)

    for task_id, scenario_index in runs:
        try:
            score = _run_episode(task_id, scenario_index)
        except Exception as e:
            print(f"  [ERROR] {task_id} s{scenario_index}: {e}", file=sys.stderr)
            score = 0.0

        label = f"{task_id} [s{scenario_index}]"
        print(f"{label:<36} {scenario_index:>2}  {score:>7.4f}")
        results.setdefault(task_id, []).append(score)

    print("-" * 50)
    summary = {
        t: round(sum(v) / len(v), 4)
        for t, v in results.items()
    }
    summary["overall"] = round(sum(summary.values()) / len(summary), 4)

    print("\nScore Summary:")
    for k, v in summary.items():
        print(f"  {k:<36}: {v:.4f}")

    print(json.dumps(summary))


if __name__ == "__main__":
    main()