"""
server/environment.py — Core OpenEnv environment for Cloud Incident Response.

Implements the full OpenEnv interface:
  reset(task_id, scenario_index) -> Observation
  step(action)                   -> (Observation, Reward, done, info)
  state()                        -> EpisodeState

All state is in-memory. Thread-safe via a lock.
"""

from __future__ import annotations

import uuid
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tasks import get_task, get_scenario
from graders import grade, _svc_match
from server.models import Action, ActionParameters, Observation, Reward, EpisodeState

# ── Action type classification ────────────────────────────────────────────────

_DIAGNOSTIC = frozenset({
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
})

_REMEDIATION = frozenset({
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
})

_SUBMIT = frozenset({
    "submit_severity", "submit_root_cause", "submit_resolution",
})

# ── Reward constants ──────────────────────────────────────────────────────────

R_QUERY_FIRST   = +0.05
R_QUERY_REPEAT  = +0.01
R_QUERY_UNKNOWN = -0.05
R_REM_GOOD      = +0.10
R_REM_WRONG     = -0.10
R_PAST_HALF     = -0.02
R_TIMEOUT       = -0.10
R_BAD_ACTION    = -0.03


class IncidentEnvironment:
    """
    OpenEnv environment for Cloud Incident Response.
    One instance handles one episode at a time (thread-safe).
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._s:        dict = {}
        self._scenario: dict = {}
        self._task_def: dict = {}
        self._ready          = False

    # ── Public OpenEnv API ───────────────────────────────────────────────────

    def reset(self, task_id: str, scenario_index: int = 0) -> Observation:
        with self._lock:
            task_def = get_task(task_id)
            scenario = get_scenario(task_id, scenario_index)

            self._task_def = task_def
            self._scenario = scenario
            self._s = {
                "episode_id":        str(uuid.uuid4()),
                "task_id":           task_id,
                "scenario_id":       scenario["scenario_id"],
                "step_count":        0,
                "max_steps":         task_def["max_steps"],
                "action_history":    [],
                "queried_data":      {},
                "queried_keys":      set(),
                "submitted":         False,
                "resolved":          False,
                "done":              False,
                "cumulative_reward": 0.0,
                "feedback":          f"Episode started. {scenario['description']}",
            }
            self._ready = True
            return self._build_obs()

    def step(self, action: Action) -> tuple[Observation, Reward, bool, dict]:
        with self._lock:
            if not self._ready:
                raise RuntimeError("Call reset() before step().")

            s = self._s
            if s["done"]:
                return (
                    self._build_obs(),
                    Reward(value=0.0, reason="episode already done",
                           cumulative=s["cumulative_reward"]),
                    True,
                    {},
                )

            s["step_count"] += 1
            step_num = s["step_count"]
            at       = action.action_type
            params   = action.parameters

            s["action_history"].append({
                "action_type": at,
                "parameters":  params.model_dump(exclude_none=True),
                "step":        step_num,
            })

            r  = 0.0
            fb: list[str] = []

            # Efficiency penalty after halfway point
            if step_num > s["max_steps"] // 2:
                r += R_PAST_HALF
                fb.append("efficiency penalty")

            if at in _DIAGNOSTIC:
                r, fb = self._handle_diagnostic(at, params, r, fb)
            elif at in _REMEDIATION:
                r, fb = self._handle_remediation(at, params, r, fb)
            elif at in _SUBMIT:
                r, fb, terminal = self._handle_submit(at, params, r, fb)
                if terminal:
                    s["done"] = True
            else:
                r += R_BAD_ACTION
                fb.append(f"unknown action_type '{at}'")

            # Timeout if max steps reached without submission
            if step_num >= s["max_steps"] and not s["done"]:
                r += R_TIMEOUT
                fb.append("timeout — no submission made")
                s["done"] = True

            # Apply grader score on terminal step
            if s["done"]:
                result = grade(s["task_id"], s, self._scenario)
                s["cumulative_reward"] = round(
                    s["cumulative_reward"] + r + result["total"], 4
                )
                fb.append(f"grader={result['feedback']}")
            else:
                s["cumulative_reward"] = round(s["cumulative_reward"] + r, 4)

            s["feedback"] = " | ".join(fb) if fb else "ok"

            return (
                self._build_obs(),
                Reward(
                    value=round(r, 4),
                    reason=s["feedback"],
                    cumulative=s["cumulative_reward"],
                ),
                s["done"],
                {"step": step_num, "feedback": s["feedback"]},
            )

    def state(self) -> EpisodeState:
        with self._lock:
            if not self._ready:
                raise RuntimeError("No active episode — call reset() first.")
            s = self._s
            return EpisodeState(
                episode_id=s["episode_id"],
                task_id=s["task_id"],
                scenario_id=s["scenario_id"],
                step_count=s["step_count"],
                max_steps=s["max_steps"],
                action_history=list(s["action_history"]),
                queried_data=dict(s["queried_data"]),
                submitted=s["submitted"],
                resolved=s["resolved"],
                done=s["done"],
                cumulative_reward=s["cumulative_reward"],
                feedback=s["feedback"],
            )

    # ── Action handlers ──────────────────────────────────────────────────────

    def _handle_diagnostic(
        self, at: str, params: ActionParameters, r: float, fb: list[str]
    ) -> tuple[float, list[str]]:
        s       = self._s
        service = (params.service or "").lower().strip()
        known   = {sv.lower() for sv in self._scenario.get("known_services", set())}
        tool_data = self._scenario.get("tool_responses", {}).get(at, {})
        key     = (at, service)

        if service and service in known:
            if key not in s["queried_keys"]:
                r += R_QUERY_FIRST
                fb.append(f"queried {service} (+{R_QUERY_FIRST})")
                s["queried_keys"].add(key)
            else:
                r += R_QUERY_REPEAT
                fb.append(f"re-queried {service} (+{R_QUERY_REPEAT})")
            result = tool_data.get(service, f"No data available for '{service}'.")
            s["queried_data"].setdefault(at, {})[service] = result

        elif service:
            r += R_QUERY_UNKNOWN
            fb.append(f"unknown service '{service}' ({R_QUERY_UNKNOWN})")
        else:
            fb.append(f"{at}: no service specified")

        return r, fb

    def _handle_remediation(
        self, at: str, params: ActionParameters, r: float, fb: list[str]
    ) -> tuple[float, list[str]]:
        s       = self._s
        service = (params.service or "").lower().strip()
        flag    = (params.flag or "").lower().strip()
        runbook = (params.runbook_action or "").lower().strip()
        target  = (params.target or "").lower().strip()

        # Build candidate keys for wrong-action matching
        keys: set[str] = {at}
        if service: keys.add(f"{at}:{service}")
        if flag:    keys.add(f"{at}:{flag}")
        if runbook: keys.add(f"execute_runbook_step:{runbook}")
        if target:  keys.add(f"execute_runbook_step:{target}")

        wrong_map  = self._scenario.get("wrong_actions", {})
        rem_data   = self._scenario.get("remediation_data", {})

        # Check for wrong actions — also use fuzzy service matching for `at:svc` keys
        is_wrong = any(k in wrong_map for k in keys)
        if not is_wrong and service:
            # Try _svc_match against wrong action keys of the form `at:svc`
            for wk in wrong_map:
                if ":" in wk:
                    w_at, w_svc = wk.split(":", 1)
                    if w_at == at and _svc_match(service, w_svc):
                        is_wrong = True
                        break

        if is_wrong:
            r += R_REM_WRONG
            reason = next(
                (wrong_map[k] for k in keys if k in wrong_map),
                "wrong action for this incident"
            )
            fb.append(f"wrong action '{at}': {str(reason)[:80]}")
        else:
            r += R_REM_GOOD
            fb.append(f"executed {at}" + (f" on '{service}'" if service else ""))
            at_data = rem_data.get(at, {})
            result  = (
                at_data.get(service) or at_data.get(flag)
                or at_data.get(runbook) or at_data.get(target)
                or "action executed successfully"
            )
            s["queried_data"].setdefault(at, {})[
                service or flag or runbook or target or at
            ] = result

        return r, fb

    def _handle_submit(
        self, at: str, params: ActionParameters, r: float, fb: list[str]
    ) -> tuple[float, list[str], bool]:
        s = self._s
        s["submitted"] = True

        if at == "submit_severity":
            fb.append(f"submitted severity: {(params.severity or '').upper()}")

        elif at == "submit_root_cause":
            fb.append(
                f"submitted root cause: "
                f"service={params.service or ''}, "
                f"failure_mode={params.failure_mode or ''}"
            )

        elif at == "submit_resolution":
            summary   = params.summary or ""
            inv_count = sum(
                1 for a in s["action_history"]
                if a.get("action_type") in _DIAGNOSTIC | _REMEDIATION
            )
            if summary.strip() and inv_count >= 1:
                s["resolved"] = True
                fb.append("resolution submitted — incident resolved")
            else:
                fb.append("resolution submitted — insufficient investigation")

        return r, fb, True

    # ── Build observation ────────────────────────────────────────────────────

    def _build_obs(self) -> Observation:
        s  = self._s
        sc = self._scenario
        td = self._task_def

        # Return sorted list of known service names (exact strings agents must use)
        known = sorted(sc.get("known_services", set()))

        return Observation(
            episode_id=s["episode_id"],
            task_id=s["task_id"],
            scenario_id=s["scenario_id"],
            step_count=s["step_count"],
            max_steps=s["max_steps"],
            incident_summary=sc.get("incident_summary", sc.get("description", "")),
            alert=sc.get("alert", {}),
            available_actions=td.get("available_actions", []),
            queried_data=dict(s["queried_data"]),
            cumulative_reward=s["cumulative_reward"],
            done=s["done"],
            feedback=s["feedback"],
            known_services=known,
        )