"""
graders.py — Deterministic graders for all 3 SRE Incident Response tasks.

Public API:
    grade(task_id, state, scenario) -> {"total": float, "breakdown": dict, "feedback": str}

All scores are in [0.0, 1.0]. Graders are deterministic and reproducible.
"""

from __future__ import annotations


def grade(task_id: str, state: dict, scenario: dict) -> dict:
    """
    Entry point. Routes to the correct task grader.

    Args:
        task_id:  One of alert_classification, root_cause_analysis, remediation_planning
        state:    Current episode state dict from IncidentEnvironment
        scenario: The scenario dict that was loaded for this episode

    Returns:
        {
            "total":     float in [0.0, 1.0],
            "breakdown": dict of sub-scores,
            "feedback":  human-readable string
        }
    """
    graders = {
        "alert_classification": _grade_alert_classification,
        "root_cause_analysis":  _grade_root_cause_analysis,
        "remediation_planning": _grade_remediation_planning,
    }
    if task_id not in graders:
        return {"total": 0.0, "breakdown": {}, "feedback": f"Unknown task_id: {task_id}"}
    return graders[task_id](state, scenario)


# ── Task 1: Alert Classification ────────────────────────────────────────────

def _grade_alert_classification(state: dict, scenario: dict) -> dict:
    """
    Scoring:
      1.0 — exact severity match
      0.5 — adjacent severity (one level off)
      0.25 — two levels off
      0.0  — opposite end or no submission
    """
    action_history = state.get("action_history", [])
    correct = scenario.get("correct_severity", "P1")
    adjacent = scenario.get("adjacent_severities", [])

    submitted_severity = None
    for action in action_history:
        if action.get("action_type") == "submit_severity":
            submitted_severity = (
                action.get("parameters", {}).get("severity", "")
                .upper()
                .strip()
            )
            break

    if not submitted_severity:
        return {
            "total": 0.0,
            "breakdown": {"severity_match": 0.0, "submitted": False},
            "feedback": "No severity submitted — score 0.0",
        }

    severity_order = ["P1", "P2", "P3", "P4"]

    if submitted_severity == correct:
        score = 1.0
        feedback = f"Exact match: {submitted_severity} == {correct}"
    elif submitted_severity in adjacent:
        score = 0.5
        feedback = f"Adjacent severity: submitted {submitted_severity}, correct {correct}"
    else:
        # Distance-based fallback
        try:
            dist = abs(severity_order.index(submitted_severity) - severity_order.index(correct))
        except ValueError:
            dist = 4
        if dist == 2:
            score = 0.25
        else:
            score = 0.0
        feedback = f"Wrong severity: submitted {submitted_severity}, correct {correct} (dist={dist})"

    return {
        "total": score,
        "breakdown": {
            "submitted_severity": submitted_severity,
            "correct_severity": correct,
            "severity_match": score,
        },
        "feedback": feedback,
    }


# ── Task 2: Root Cause Analysis ─────────────────────────────────────────────

def _grade_root_cause_analysis(state: dict, scenario: dict) -> dict:
    """
    Scoring:
      Base score (0.0–0.6):
        0.6 — correct service AND correct failure_mode
        0.35 — correct service only
        0.0  — wrong service
      Efficiency bonus (0.0–0.4):
        Based on how many unique relevant services were queried before submitting.
        More targeted = higher bonus (penalises random querying).
    """
    action_history = state.get("action_history", [])
    correct_rc = scenario.get("correct_root_cause", {})
    correct_service = correct_rc.get("service", "").lower().strip()
    correct_mode = correct_rc.get("failure_mode", "").lower().strip()
    known_services = {s.lower() for s in scenario.get("known_services", set())}

    # Find the submit_root_cause action
    submitted_service = ""
    submitted_mode = ""
    submit_step = None
    for action in action_history:
        if action.get("action_type") == "submit_root_cause":
            params = action.get("parameters", {})
            submitted_service = params.get("service", "").lower().strip()
            submitted_mode = params.get("failure_mode", "").lower().strip()
            submit_step = action.get("step", len(action_history))
            break

    if not submitted_service:
        return {
            "total": 0.0,
            "breakdown": {"base": 0.0, "efficiency": 0.0, "submitted": False},
            "feedback": "No root cause submitted — score 0.0",
        }

    # Base score
    service_match = submitted_service == correct_service
    mode_keywords = [w for w in correct_mode.split() if len(w) > 3]
    mode_match = service_match and any(
        kw in submitted_mode for kw in mode_keywords
    ) if mode_keywords else service_match

    if mode_match:
        base = 0.6
        base_feedback = f"Correct service ({submitted_service}) + failure mode matched"
    elif service_match:
        base = 0.35
        base_feedback = f"Correct service ({submitted_service}) but failure mode unclear"
    else:
        base = 0.0
        base_feedback = f"Wrong service: submitted '{submitted_service}', correct '{correct_service}'"

    # Efficiency bonus — only awarded if service was correct
    efficiency = 0.0
    if service_match and submit_step is not None:
        diagnostic_actions = {"query_logs", "check_metrics", "check_dependencies",
                               "check_recent_deploys", "check_service_status"}
        queried = {
            a.get("parameters", {}).get("service", "").lower()
            for a in action_history[:submit_step]
            if a.get("action_type") in diagnostic_actions
        }
        relevant_queried = queried & known_services
        # Reward for querying relevant services efficiently
        # Full bonus for querying 2-3 key services; less for spraying all services
        total_queries = sum(
            1 for a in action_history[:submit_step]
            if a.get("action_type") in diagnostic_actions
        )
        if total_queries > 0:
            precision = len(relevant_queried) / max(total_queries, 1)
            efficiency = round(min(0.4, precision * 0.4 + min(len(relevant_queried), 3) * 0.05), 4)

    total = round(min(1.0, base + efficiency), 4)

    return {
        "total": total,
        "breakdown": {
            "base": base,
            "efficiency_bonus": efficiency,
            "service_match": service_match,
            "mode_match": mode_match,
            "submitted_service": submitted_service,
            "correct_service": correct_service,
        },
        "feedback": f"{base_feedback} | efficiency bonus: {efficiency:.2f} | total: {total:.2f}",
    }


# ── Task 3: Remediation Planning ────────────────────────────────────────────

def _grade_remediation_planning(state: dict, scenario: dict) -> dict:
    """
    Scoring:
      Resolution base (0.0 or 0.6):
        0.6 — submit_resolution with non-empty summary after ≥1 investigation action
      Efficiency bonus (0.0–0.3):
        Fraction of correct remediation actions executed (from correct_remediation_sequence)
      Wrong action penalty (up to -0.15):
        -0.05 per wrong action (capped at -0.15)
      Summary quality bonus (0.0–0.1):
        +0.1 if summary contains ≥3 resolution keywords from scenario
    """
    action_history = state.get("action_history", [])
    correct_seq = scenario.get("correct_remediation_sequence", [])
    wrong_actions_map = scenario.get("wrong_actions", {})
    resolution_keywords = scenario.get("resolution_keywords", [])

    diagnostic_actions = {"query_logs", "check_metrics", "check_dependencies",
                           "check_recent_deploys", "check_service_status"}
    remediation_actions = {"restart_service", "rollback_deploy", "scale_service",
                           "disable_feature_flag", "clear_cache", "execute_runbook_step"}

    # Find submit_resolution
    submitted_summary = ""
    for action in action_history:
        if action.get("action_type") == "submit_resolution":
            submitted_summary = action.get("parameters", {}).get("summary", "")
            break

    investigation_count = sum(
        1 for a in action_history
        if a.get("action_type") in diagnostic_actions | remediation_actions
    )

    if not submitted_summary or investigation_count < 1:
        return {
            "total": 0.0,
            "breakdown": {"base": 0.0, "efficiency": 0.0, "penalty": 0.0, "summary": 0.0},
            "feedback": "No resolution submitted or no investigation — score 0.0",
        }

    base = 0.6

    # Efficiency bonus — which correct actions were executed?
    executed_action_keys = set()
    for a in action_history:
        at = a.get("action_type", "")
        svc = a.get("parameters", {}).get("service", "")
        flag = a.get("parameters", {}).get("flag", "")
        step_action = a.get("parameters", {}).get("runbook_action", "")
        target = a.get("parameters", {}).get("target", "")
        # Build key variants that match correct_remediation_sequence format
        executed_action_keys.add(at)
        if svc:
            executed_action_keys.add(f"{at}:{svc}")
        if flag:
            executed_action_keys.add(f"{at}:{flag}")
        if step_action:
            executed_action_keys.add(f"execute_runbook_step:{step_action}")
        if target:
            executed_action_keys.add(f"execute_runbook_step:{target}")

    matched = sum(1 for key in correct_seq if key in executed_action_keys)
    efficiency = round((matched / len(correct_seq)) * 0.3, 4) if correct_seq else 0.0

    # Wrong action penalty
    wrong_count = 0
    for a in action_history:
        at = a.get("action_type", "")
        svc = a.get("parameters", {}).get("service", "")
        key1 = at
        key2 = f"{at}:{svc}"
        if key1 in wrong_actions_map or key2 in wrong_actions_map:
            wrong_count += 1
    penalty = round(min(0.15, wrong_count * 0.05), 4)

    # Summary quality bonus
    summary_lower = submitted_summary.lower()
    keyword_hits = sum(1 for kw in resolution_keywords if kw in summary_lower)
    summary_bonus = 0.1 if keyword_hits >= 3 else 0.05 if keyword_hits >= 1 else 0.0

    total = round(max(0.0, min(1.0, base + efficiency - penalty + summary_bonus)), 4)

    return {
        "total": total,
        "breakdown": {
            "base": base,
            "efficiency_bonus": efficiency,
            "wrong_action_penalty": -penalty,
            "summary_bonus": summary_bonus,
            "correct_actions_matched": matched,
            "correct_actions_total": len(correct_seq),
            "wrong_actions_count": wrong_count,
            "summary_keywords_hit": keyword_hits,
        },
        "feedback": (
            f"base={base} | efficiency={efficiency:.2f} ({matched}/{len(correct_seq)} correct actions) "
            f"| penalty=-{penalty:.2f} | summary_bonus={summary_bonus:.2f} | total={total:.2f}"
        ),
    }
