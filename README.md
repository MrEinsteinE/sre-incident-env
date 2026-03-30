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

| ID | Incident Type | Root Cause | Failure Pattern |
|---|---|---|---|
| AC-001 | DB connection pool exhaustion | postgres-db / auth-service deploy | api-gateway → auth-service → postgres-db cascade |
| AC-002 | CDN cache invalidation storm | cdn-edge purge cronjob misconfigured | 40× origin traffic spike |
| RCA-001 | Postgres OOM kill | analytics-service unbounded query | Kernel OOM → DB crash loop → all dependents down |
| RCA-002 | BGP network partition | network-infra config change | Route withdrawal → AZ isolation → 61% checkout failures |
| RP-001 | Full OOM remediation | analytics-service | Disable job → restart DB → restore services → document |
| RP-002 | Full BGP remediation | network-infra | Restore routes → rollback config → verify recovery → document |

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
{"action_type": "rollback_deploy",      "parameters": {"service": "network-infra", "target_version": "previous"}}
{"action_type": "scale_service",        "parameters": {"service": "image-service", "replicas": 10}}
{"action_type": "disable_feature_flag", "parameters": {"flag": "full_history_export"}}
{"action_type": "execute_runbook_step", "parameters": {"runbook_action": "restore_bgp_routes"}}
```

**Submission actions** (end the episode):
```json
{"action_type": "submit_severity",   "parameters": {"severity": "P1", "service": "postgres-db"}}
{"action_type": "submit_root_cause", "parameters": {"service": "analytics-service", "failure_mode": "unbounded query OOM killing postgres-db"}}
{"action_type": "submit_resolution", "parameters": {"summary": "Disabled analytics job, restarted postgres-db..."}}
```

## Observation Space

| Field | Type | Description |
|---|---|---|
| `episode_id` | string | Unique episode UUID |
| `task_id` | string | Active task |
| `scenario_id` | string | Scenario (e.g. `AC-001`) |
| `step_count` / `max_steps` | int | Current step and budget |
| `incident_summary` | string | Plain-text incident description |
| `alert` | dict | Alert payload with severity, symptoms, affected services |
| `available_actions` | list[str] | Valid action types for this task |
| `queried_data` | dict | All tool responses gathered so far |
| `known_services` | list[str] | Exact service names to use in actions |
| `cumulative_reward` | float | Running reward total |
| `done` | bool | Episode terminal flag |
| `feedback` | string | Per-step feedback string |

## Reward Function

Dense reward shaping throughout the trajectory:

| Event | Reward |
|---|---|
| Query known service (first time) | +0.05 |
| Query known service (repeat) | +0.01 |
| Query unknown service | −0.05 |
| Correct remediation action | +0.10 |
| Wrong remediation action | −0.10 |
| Step past halfway (non-submit) | −0.02 |
| Timeout without submission | −0.10 |
| Grader score (terminal step) | 0.0–1.0 |

**Grader scoring** (deterministic, via `GET /grader`):

| Task | Scoring Logic |
|---|---|
| `alert_classification` | 1.0 exact · 0.5 adjacent · 0.25 two-off · 0.0 wrong/none |
| `root_cause_analysis` | 0.6 base (svc+mode) + up to 0.4 efficiency bonus |
| `remediation_planning` | 0.6 base + 0.3 efficiency − 0.15 wrong penalty + 0.1 summary |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | `{"status":"running",...}` — HF Space health |
| GET | `/health` | `{"status":"ok","version":"0.1.0"}` |
| POST | `/reset?task_id=...&scenario_index=...` | Start new episode |
| POST | `/step` | Submit action (JSON body) |
| GET | `/state` | Full current episode state |
| GET | `/tasks` | All tasks with action schemas |
| GET | `/grader` | Score current episode (0.0–1.0) |
| POST | `/baseline` | Run inference.py, return scores |

## Setup & Usage

### Local development
```bash
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Docker
```bash
docker build -t cloud-incident-env .
docker run -p 7860:7860 \
  -e API_BASE_URL="https://api-inference.huggingface.co/v1" \
  -e MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct" \
  -e HF_TOKEN="hf_your_token" \
  cloud-incident-env
```

### Run inference script
```bash
export API_BASE_URL="https://api-inference.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export HF_TOKEN="hf_your_token"
python inference.py
```

### Quick API test
```bash
# Start new episode
curl -X POST "http://localhost:7860/reset?task_id=alert_classification&scenario_index=0"

# Submit an action
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type":"query_logs","parameters":{"service":"api-gateway"}}'

# Check score
curl http://localhost:7860/grader
```

## Baseline Scores

Using `meta-llama/Llama-3.1-8B-Instruct` via HF Inference API:

| Task | Scenario 0 | Scenario 1 | Average |
|---|---|---|---|
| `alert_classification` | ~1.00 | ~0.50 | ~0.75 |
| `root_cause_analysis` | ~0.45 | ~0.35 | ~0.40 |
| `remediation_planning` | ~0.25 | ~0.20 | ~0.23 |
| **overall** | | | **~0.46** |

*Run `python inference.py` to reproduce.*

## Project Structure

```
.
├── Dockerfile
├── README.md
├── requirements.txt
├── openenv.yaml
├── tasks.py          # Scenario definitions (6 scenarios across 3 tasks)
├── graders.py        # Deterministic graders for all tasks
├── inference.py      # Baseline agent + smart fallback logic
└── server/
    ├── __init__.py
    ├── app.py        # FastAPI endpoints
    ├── environment.py # Core OpenEnv step/reset/state logic
    └── models.py     # Typed Pydantic models (Action, Observation, Reward)
```