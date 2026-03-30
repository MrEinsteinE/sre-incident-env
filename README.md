---
title: SRE Incident Response OpenEnv
emoji: 🚨
colorFrom: red
colorTo: blue
sdk: docker
app_port: 7860
tags:
  - openenv
  - sre
  - devops
  - incident-response
  - real-world
  - agentic
---

# SRE Incident Response — OpenEnv Environment

An OpenEnv environment for training and evaluating AI agents on Site Reliability Engineering (SRE) tasks. Agents handle real production incident scenarios: triaging alerts, identifying root causes through log/metric correlation, and executing remediation runbooks to resolve cascading failures.

## Why This Environment

Every cloud company employs SREs who respond to production incidents under time pressure. This environment simulates the exact decision loop an on-call SRE follows:

1. **Triage** — Read alert payload, assess blast radius, classify severity (P1–P4)
2. **Investigate** — Query logs, metrics, dependency graphs, recent deploys
3. **Diagnose** — Correlate signals across services to find the root cause
4. **Remediate** — Execute the correct runbook steps in the right order
5. **Document** — Submit a resolution summary for post-incident review

Scenarios include cascading DB failures, CDN cache storms, OOM kills, and BGP network partitions — all modeled from real production incident patterns.

## Tasks

| Task ID | Difficulty | Max Steps | Description |
|---|---|---|---|
| `alert_classification` | Easy | 3 | Classify alert severity (P1–P4) from metrics and symptoms |
| `root_cause_analysis` | Medium | 10 | Trace logs/metrics/deps to find root cause service + failure mode |
| `remediation_planning` | Hard | 15 | Diagnose, remediate, and document full incident resolution |

Each task has 2 scenarios:

| Scenario | Incident Type |
|---|---|
| AC-001 | Cascading DB connection pool exhaustion (postgres → auth → api-gateway) |
| AC-002 | CDN cache invalidation storm (misconfigured purge → 40× origin traffic) |
| RCA-001 | Postgres OOM kill by runaway analytics query |
| RCA-002 | BGP route withdrawal → AZ network partition → 61% checkout failures |
| RP-001 | Full OOM remediation (stop job → restart DB → restore services) |
| RP-002 | Full BGP remediation (restore routes → roll back config → verify recovery) |

## Action Space

**Diagnostic:**
```json
{"action_type": "query_logs",           "parameters": {"service": "postgres-db"}}
{"action_type": "check_metrics",        "parameters": {"service": "auth-service"}}
{"action_type": "check_dependencies",   "parameters": {"service": "api-gateway"}}
{"action_type": "check_recent_deploys", "parameters": {"service": "analytics-service"}}
{"action_type": "check_service_status", "parameters": {"service": "payment-service"}}
```

**Remediation:**
```json
{"action_type": "restart_service",      "parameters": {"service": "postgres-db"}}
{"action_type": "rollback_deploy",      "parameters": {"service": "network-infra", "target_version": "previous"}}
{"action_type": "scale_service",        "parameters": {"service": "image-service", "replicas": 10}}
{"action_type": "disable_feature_flag", "parameters": {"flag": "full_history_export"}}
{"action_type": "execute_runbook_step", "parameters": {"runbook_action": "restore_bgp_routes"}}
```

**Submission:**
```json
{"action_type": "submit_severity",   "parameters": {"severity": "P1", "service": "postgres-db"}}
{"action_type": "submit_root_cause", "parameters": {"service": "analytics-service", "failure_mode": "unbounded query OOM"}}
{"action_type": "submit_resolution", "parameters": {"summary": "Disabled analytics cron job, restarted postgres-db..."}}
```

## Observation Space

Each step returns:

| Field | Type | Description |
|---|---|---|
| `episode_id` | string | Unique episode UUID |
| `task_id` | string | Active task |
| `scenario_id` | string | Scenario identifier (e.g. `AC-001`) |
| `step_count` / `max_steps` | int | Current step and budget |
| `incident_summary` | string | Plain-text incident description |
| `alert` | dict | Alert payload with severity, affected services, symptoms |
| `available_actions` | list | Valid action types for this task |
| `queried_data` | dict | All tool responses gathered so far |
| `cumulative_reward` | float | Running reward total |
| `done` | bool | Episode terminal flag |
| `feedback` | string | Per-step feedback string |

## Reward Function

| Event | Reward |
|---|---|
| Query known service (first time) | +0.05 |
| Query known service (repeat) | +0.01 |
| Query unknown service | -0.05 |
| Correct remediation action | +0.10 |
| Wrong remediation action | -0.10 |
| Step past halfway (non-submit) | -0.02 |
| Timeout without submission | -0.10 |
| Grader score (on terminal step) | 0.0–1.0 |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | `{"status": "ok", "version": "0.1.0"}` |
| POST | `/reset?task_id=...&scenario_index=...` | Start new episode |
| POST | `/step` | Submit action (JSON body) |
| GET | `/state` | Full current episode state |
| GET | `/tasks` | All tasks with schemas |
| GET | `/grader` | Score current episode (0.0–1.0) |
| POST | `/baseline` | Run inference.py, return scores |

## Setup

```bash
# Local development
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860

# Docker
docker build -t sre-incident-env .
docker run -p 7860:7860 \
  -e API_BASE_URL="https://api.groq.com/openai/v1" \
  -e MODEL_NAME="llama-3.1-8b-instant" \
  -e HF_TOKEN="your_api_key" \
  sre-incident-env

# Run baseline inference
export API_BASE_URL="https://api.groq.com/openai/v1"
export MODEL_NAME="llama-3.1-8b-instant"
export HF_TOKEN="your_groq_key"
python inference.py
```

## Baseline Scores

Using `llama-3.1-8b-instant` via Groq:

| Task | Score |
|---|---|
| `alert_classification` | ~0.75 |
| `root_cause_analysis` | ~0.35 |
| `remediation_planning` | ~0.20 |
| **overall** | **~0.43** |

*Run `python inference.py` to reproduce.*
