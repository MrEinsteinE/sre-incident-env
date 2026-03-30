"""
server/environment.py — Core OpenEnv environment for SRE Incident Response.

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

from tasks import ALL_TASKS, get_task, get_scenario
from graders import grade
from server.models import Action, ActionParameters, Observation, Reward, EpisodeState

# ── Action type sets ─────────────────────────────────────────────────────────

_DIAGNOSTIC = {
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
}

_REMEDIATION = {
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
}

_SUBMIT = {
    "submit_severity", "submit_root_cause", "submit_resolution",
}

# ── Reward constants ─────────────────────────────────────────────────────────

R_QUERY_KNOWN_FIRST  = +0.05
R_QUERY_KNOWN_REPEAT = +0.01
R_QUERY_UNKNOWN      = -0.05
R_REMEDIATION_GOOD   = +0.10
R_REMEDIATION_WRONG  = -0.10
R_STEP_PAST_HALF     = -0.02
R_TIMEOUT            = -0.10
R_UNKNOWN_ACTION     = -0.03


class IncidentEnvironment:
    """
    OpenEnv environment for SRE Incident Response.
    One instance handles one episode at a time.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._s: dict = {}
        self._scenario: dict = {}
        self._task_def: dict = {}
        self._ready = False

    # ── Public OpenEnv API ───────────────────────────────────────────────────

    def reset(self, task_id: str, scenario_index: int = 0) -> Observation:
        """Start a fresh episode. Returns the initial Observation."""
        with self._lock:
            task_def = get_task(task_id)
            scenario = get_scenario(task_id, scenario_index)

            self._task_def = task_def
            self._scenario = scenario
            self._s = {
                "episode_id":       str(uuid.uuid4()),
                "task_id":          task_id,
                "scenario_id":      scenario["scenario_id"],
                "step_count":       0,
                "max_steps":        task_def["max_steps"],
                "action_history":   [],
                "queried_data":     {},
                "queried_keys":     set(),   # tracks (action_type, service) for repeat detection
                "submitted":        False,
                "resolved":         False,
                "done":             False,
                "cumulative_reward": 0.0,
                "feedback":         f"Episode started. {scenario['description']}",
            }
            self._ready = True
            return self._build_obs()

    def step(self, action: Action) -> tuple[Observation, Reward, bool, dict]:
        """Process one agent action. Returns (Observation, Reward, done, info)."""
        with self._lock:
            if not self._ready:
                raise RuntimeError("Call reset() before step().")

            s = self._s
            if s["done"]:
                obs = self._build_obs()
                return obs, Reward(value=0.0, reason="episode already done",
                                   cumulative=s["cumulative_reward"]), True, {}

            s["step_count"] += 1
            step_num = s["step_count"]
            max_steps = s["max_steps"]
            at = action.action_type
            params = action.parameters

            # Record action
            s["action_history"].append({
                "action_type": at,
                "parameters":  params.model_dump(exclude_none=True),
                "step":        step_num,
            })

            # ── Compute step reward ──────────────────────────────────────────
            r = 0.0
            fb: list[str] = []

            # Efficiency penalty past halfway
            if step_num > max_steps // 2:
                r += R_STEP_PAST_HALF
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
                r += R_UNKNOWN_ACTION
                fb.append(f"unknown action_type '{at}'")

            # Timeout
            if step_num >= max_steps and not s["done"]:
                r += R_TIMEOUT
                fb.append("timeout — no submission made")
                s["done"] = True

            # Run grader on terminal step
            if s["done"]:
                result = grade(s["task_id"], s, self._scenario)
                s["cumulative_reward"] = round(
                    s["cumulative_reward"] + result["total"], 4
                )
                fb.append(f"grader → {result['feedback']}")

            s["cumulative_reward"] = round(s["cumulative_reward"] + r, 4)
            s["feedback"] = " | ".join(fb) if fb else "ok"

            reward_obj = Reward(
                value=round(r, 4),
                reason=s["feedback"],
                cumulative=s["cumulative_reward"],
            )
            return self._build_obs(), reward_obj, s["done"], {"step": step_num, "feedback": s["feedback"]}

    def state(self) -> EpisodeState:
        """Return the full current episode state."""
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
                action_history=s["action_history"],
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
        s = self._s
        service = (params.service or "").lower().strip()
        known = {sv.lower() for sv in self._scenario.get("known_services", set())}
        tool_data = self._scenario.get("tool_responses", {}).get(at, {})
        query_key = (at, service)

        if service and service in known:
            if query_key not in s["queried_keys"]:
                r += R_QUERY_KNOWN_FIRST
                fb.append(f"queried {service} (+{R_QUERY_KNOWN_FIRST})")
                s["queried_keys"].add(query_key)
            else:
                r += R_QUERY_KNOWN_REPEAT
                fb.append(f"re-queried {service} (+{R_QUERY_KNOWN_REPEAT})")

            result = tool_data.get(service, f"No data for '{service}'.")
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
        s = self._s
        service = (params.service or "").lower().strip()
        flag = (params.flag or "").lower().strip()
        runbook_action = (params.runbook_action or "").lower().strip()
        target = (params.target or "").lower().strip()

        # Build lookup keys
        keys_to_check = {at}
        if service:
            keys_to_check.add(f"{at}:{service}")
        if flag:
            keys_to_check.add(f"{at}:{flag}")
        if runbook_action:
            keys_to_check.add(f"execute_runbook_step:{runbook_action}")
        if target:
            keys_to_check.add(f"execute_runbook_step:{target}")

        wrong_map = self._scenario.get("wrong_actions", {})
        rem_data = self._scenario.get("remediation_data", {})

        is_wrong = any(k in wrong_map for k in keys_to_check)

        if is_wrong:
            r += R_REMEDIATION_WRONG
            reason = next((wrong_map[k] for k in keys_to_check if k in wrong_map), "wrong action")
            fb.append(f"wrong: {at} — {str(reason)[:80]}")
        else:
            r += R_REMEDIATION_GOOD
            fb.append(f"executed {at}" + (f" on {service}" if service else ""))
            # Store remediation result if available
            at_data = rem_data.get(at, {})
            result = (
                at_data.get(service)
                or at_data.get(flag)
                or at_data.get(runbook_action)
                or at_data.get(target)
                or "action executed"
            )
            s["queried_data"].setdefault(at, {})[service or flag or runbook_action or at] = result

        return r, fb

    def _handle_submit(
        self, at: str, params: ActionParameters, r: float, fb: list[str]
    ) -> tuple[float, list[str], bool]:
        s = self._s
        s["submitted"] = True

        if at == "submit_severity":
            severity = (params.severity or "").upper()
            fb.append(f"submitted severity: {severity}")

        elif at == "submit_root_cause":
            svc = params.service or ""
            mode = params.failure_mode or ""
            fb.append(f"submitted root cause: service={svc}, failure_mode={mode}")

        elif at == "submit_resolution":
            summary = params.summary or ""
            diag_rem_count = sum(
                1 for a in s["action_history"]
                if a.get("action_type") in _DIAGNOSTIC | _REMEDIATION
            )
            if summary.strip() and diag_rem_count >= 1:
                s["resolved"] = True
                fb.append("resolution submitted — incident resolved")
            else:
                fb.append("resolution submitted (insufficient investigation)")

        return r, fb, True  # always terminal

    # ── Build observation ────────────────────────────────────────────────────

    def _build_obs(self) -> Observation:
        s = self._s
        sc = self._scenario
        td = self._task_def
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
        )
