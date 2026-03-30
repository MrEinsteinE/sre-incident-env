---
title: Cloud Incident Response OpenEnv
emoji: 🚨
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
tags:
  - openenv
  - sre
  - cloud
  - incident-response
  - devops
  - real-world
  - agentic
---

# Cloud Incident Response — OpenEnv Environment

An OpenEnv environment for training and evaluating AI agents on **cloud SRE incident response** — the real-world on-call workflow that engineers at every cloud company perform daily.

Distinct from Kubernetes operations environments: this focuses on **cross-service cascading failures** in distributed microservice architectures — connection pool exhaustion, CDN cache storms, OOM kills, and BGP network partitions.

## Why This Environment

Every cloud company employs SREs who respond to production incidents under time pressure with incomplete information. This environment simulates the exact decision loop:

1. **Triage** — Read alert, assess blast radius, classify severity (P1–P4)
2. **Investigate** — Query logs, metrics, dependencies, recent deploys
3. **Diagnose** — Correlate signals across services to find the root cause
4. **Remediate** — Execute the correct runbook steps in the right sequence
5. **Document** — Submit a resolution summary for post-incident review

Agents trained here learn the same skills a human SRE uses: service dependency traversal, log correlation, cascading failure analysis, and targeted remediation.

## Tasks

| Task ID | Difficulty | Max Steps | What the Agent Does |
|---|---|---|---|
| `alert_classification` | Easy | 3 | Classify alert severity (P1–P4) from metrics and symptoms |
| `root_cause_analysis` | Medium | 10 | Trace logs/metrics/deps to find root cause service and failure mode |
| `remediation_planning` | Hard | 15 | Diagnose, remediate, and document full incident resolution |

### Scenarios

| ID | Incident Type | Failure Pattern |
|---|---|---|
| AC-001 | DB connection pool exhaustion | postgres-db → auth-service → api-gateway cascade |
| AC-002 | CDN cache invalidation storm | Misconfigured purge job → 40× origin traffic |
| RCA-001 | Postgres OOM kill | Runaway analytics query → kernel OOM → all dependents down |
| RCA-002 | BGP network partition | Route withdrawal → AZ isolation → 61% checkout failures |
| RP-001 | Full OOM remediation | Disable job → restart DB → restore services → document |
| RP-002 | Full BGP remediation | Restore routes → rollback config → verify recovery → document |

## Action Space

**Diagnostic actions** (gather evidence):
```json
{"action_type": "query_logs",           "parameters": {"service": "postgres-db"}}
{"action_type": "check_metrics",        "parameters": {"service": "auth-service"}}
{"action_type": "check_dependencies",   "parameters": {"service": "api-gateway"}}
{"action_type": "check_recent_deploys", "parameters": {"service": "analytics-service"}}
{"action_type": "check_service_status", "parameters": {"service": "payment-service"}}
```

**Remediation actions** (fix the incident):
```json
{"action_type": "restart_service",      "parameters": {"service": "postgres-db"}}
{"action_type": "rollback_deploy",      "parameters": {"service": "network-infra"}}
{"action_type": "scale_service",        "parameters": {"service": "image-service", "replicas": 10}}
{"action_type": "disable_feature_flag", "parameters": {"flag": "full_history_export"}}
{"action_type": "execute_runbook_step", "parameters": {"runbook_action": "restore_bgp_routes"}}
```

**Submission actions** (end the episode):
```json
{"action_type": "submit_severity",   "parameters": {"severity": "P1", "service": "postgres-db"}}
{"action_type": "submit_root_cause", "parameters": {"service": "analytics-service", "failure_mode": "unbounded query OOM"}}
{"action_type": "submit_resolution", "parameters": {"summary": "Disabled analytics job, restarted postgres-db..."}}
```

## Observation Space

| Field | Type | Description |
|---|---|---|
| `episode_id` | string | Unique episode UUID |
| `task_id` | string | Active task |
| `scenario_id` | string | Scenario (e.g. `AC-001`) |
| `step_count` / `max_steps` | int | Current progress and budget |
| `incident_summary` | string | Plain-text incident description |
| `alert` | dict | Alert payload with severity, symptoms, affected services |
| `available_actions` | list[str] | Valid action types for this task |
| `queried_data` | dict | All tool responses gathered so far |
| `cumulative_reward` | float | Running reward total |
| `done` | bool | Episode terminal flag |
| `feedback` | string | Per-step feedback |

## Reward Function

Dense signals throughout the trajectory:

| Event | Reward |
|---|---|
| Query known service (first time) | +0.05 |
| Query known service (repeat) | +0.01 |
| Query unknown service | -0.05 |
| Correct remediation action | +0.10 |
| Wrong remediation action | -0.10 |
| Step past halfway (non-submit) | -0.02 |
| Timeout without submission | -0.10 |
| Grader score (terminal step) | 0.0–1.0 |

**Grader scoring** (deterministic, via `GET /grader`):

| Task | Scoring |
|---|---|
| `alert_classification` | 1.0 exact · 0.5 adjacent · 0.25 two-off · 0.0 wrong |
| `root_cause_analysis` | 0.6 base + up to 0.4 efficiency bonus |
| `remediation_planning` | 0.6 base + 0.3 efficiency − 0.15 wrong penalty + 0.1 summary |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | `{"status": "ok", "version": "0.1.0"}` |
| POST | `/reset?task_id=...&scenario_index=...` | Start new episode |
| POST | `/step` | Submit action (JSON body) |
| GET | `/state` | Full current episode state |
| GET | `/tasks` | All tasks with action schemas |
| GET | `/grader` | Score current episode (0.0–1.0) |
| POST | `/baseline` | Run inference.py, return scores |

## Setup

```bash
# Local
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860

# Docker
docker build -t cloud-incident-env .
docker run -p 7860:7860 \
  -e API_BASE_URL="https://api-inference.huggingface.co/v1" \
  -e MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct" \
  -e HF_TOKEN="hf_your_token" \
  cloud-incident-env

# Run inference script
export API_BASE_URL="https://api-inference.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export HF_TOKEN="hf_your_token"
python inference.py
```

## Baseline Scores

Using `meta-llama/Llama-3.1-8B-Instruct` via HF Inference API:

| Task | Score |
|---|---|
| `alert_classification` | ~0.75 |
| `root_cause_analysis` | ~0.35 |
| `remediation_planning` | ~0.20 |
| **overall** | **~0.43** |

*Run `python inference.py` to reproduce.*
