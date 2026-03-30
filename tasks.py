"""
tasks.py — Task and scenario definitions for Cloud Incident Response OpenEnv.

Covers cross-service cascading failures in distributed cloud systems:
  - DB connection pool exhaustion cascading through service mesh
  - CDN cache invalidation storms causing origin overload
  - OOM kills from runaway analytics queries
  - BGP network partitions isolating availability zones

Distinct from Kubernetes ops environments — focuses on application-layer
incident response: log correlation, dependency tracing, and remediation
across microservice architectures.

Public API:
    get_task(task_id)            -> task metadata dict
    get_scenario(task_id, index) -> scenario dict
    list_tasks()                 -> list of task dicts
    ALL_TASKS                    -> dict[task_id -> metadata]
"""

from __future__ import annotations

ALL_TASKS: dict = {
    "alert_classification": {
        "id": "alert_classification",
        "name": "Task 1: Alert Severity Classification",
        "difficulty": "easy",
        "max_steps": 3,
        "score_range": [0.0, 1.0],
        "description": (
            "An alert has fired. Query logs and metrics across affected services, "
            "then classify the incident severity: P1 (CRITICAL — revenue/user impact, "
            "immediate action), P2 (HIGH — degraded service), P3 (MEDIUM — minor issue), "
            "P4 (LOW — informational). Submit severity with submit_severity."
        ),
        "available_actions": [
            "query_logs",
            "check_metrics",
            "check_dependencies",
            "check_recent_deploys",
            "submit_severity",
        ],
        "submission_action": "submit_severity",
        "scenarios": 2,
    },
    "root_cause_analysis": {
        "id": "root_cause_analysis",
        "name": "Task 2: Root Cause Analysis",
        "difficulty": "medium",
        "max_steps": 10,
        "score_range": [0.0, 1.0],
        "description": (
            "A production incident is active. Use diagnostic tools to trace the failure "
            "chain across services. Query logs, metrics, dependency graphs, and recent "
            "deploys to identify which service is the root cause and what failure mode "
            "triggered the cascade. Submit findings with submit_root_cause."
        ),
        "available_actions": [
            "query_logs",
            "check_metrics",
            "check_dependencies",
            "check_recent_deploys",
            "check_service_status",
            "submit_root_cause",
        ],
        "submission_action": "submit_root_cause",
        "scenarios": 2,
    },
    "remediation_planning": {
        "id": "remediation_planning",
        "name": "Task 3: Incident Remediation",
        "difficulty": "hard",
        "max_steps": 15,
        "score_range": [0.0, 1.0],
        "description": (
            "A critical production incident requires full end-to-end resolution. "
            "Diagnose the root cause, execute the correct remediation sequence "
            "(disable feature flags, restart services, rollback deploys, run runbook steps), "
            "then submit a resolution summary. Scored on investigation quality, "
            "remediation correctness, efficiency, and documentation."
        ),
        "available_actions": [
            "query_logs",
            "check_metrics",
            "check_dependencies",
            "check_recent_deploys",
            "check_service_status",
            "restart_service",
            "rollback_deploy",
            "scale_service",
            "disable_feature_flag",
            "clear_cache",
            "execute_runbook_step",
            "submit_resolution",
        ],
        "submission_action": "submit_resolution",
        "scenarios": 2,
    },
}

# ---------------------------------------------------------------------------
# Scenario data — 3 tasks × 2 scenarios = 6 total episodes
# ---------------------------------------------------------------------------

SCENARIOS: dict = {

    # ── TASK 1: ALERT CLASSIFICATION ────────────────────────────────────────

    "alert_classification": [

        # AC-001: Cascading DB connection pool exhaustion → P1
        {
            "scenario_id": "AC-001",
            "description": (
                "Cascading failure: postgres-db connection pool exhausted, "
                "causing auth-service timeouts, blocking api-gateway requests. "
                "Revenue impact is severe and growing."
            ),
            "incident_summary": (
                "P1 ALERT — api-gateway 5xx rate 78%, auth-service timeout rate 94%, "
                "postgres-db connection pool at 100% (500/500). "
                "Checkout completely down. Revenue impact: $12,000/min."
            ),
            "alert": {
                "id":               "ALT-20240315-001",
                "title":            "CRITICAL: api-gateway error rate spike 78%",
                "severity_fired":   "P1",
                "affected_services": ["api-gateway", "auth-service", "postgres-db"],
                "symptoms": [
                    "api-gateway: HTTP 503 rate 78% (baseline: 0.1%)",
                    "auth-service: connection timeout 94% of requests",
                    "postgres-db: connection pool 500/500 — 100% utilized",
                    "checkout flow: completely unavailable",
                    "new user logins: 0% success rate",
                ],
                "error_rate":              0.78,
                "duration_minutes":        4,
                "revenue_impact_per_min":  12000,
            },
            "known_services": {"api-gateway", "auth-service", "postgres-db"},
            "tool_responses": {
                "query_logs": {
                    "api-gateway": (
                        "2024-03-15T10:04:12Z ERROR upstream connect error — "
                        "reset reason: connection timeout auth-service:8080\n"
                        "2024-03-15T10:04:13Z ERROR 503 Service Unavailable upstream: auth-service\n"
                        "2024-03-15T10:04:14Z ERROR circuit breaker OPEN for auth-service"
                    ),
                    "auth-service": (
                        "2024-03-15T10:04:10Z ERROR pq: sorry, too many clients already\n"
                        "2024-03-15T10:04:11Z ERROR dial tcp postgres-db:5432: "
                        "connect: connection refused — pool exhausted (500/500)\n"
                        "2024-03-15T10:04:12Z ERROR all connection pool slots occupied"
                    ),
                    "postgres-db": (
                        "2024-03-15T10:03:58Z LOG connection received: host=auth-service\n"
                        "2024-03-15T10:04:00Z FATAL remaining connection slots reserved "
                        "for non-replication superuser\n"
                        "2024-03-15T10:04:01Z LOG max_connections=500 active=500 idle=0"
                    ),
                },
                "check_metrics": {
                    "api-gateway": (
                        "HTTP 5xx rate: 78% | p99 latency: 30s (timeout) | "
                        "RPS: 1,200 | circuit_breaker: OPEN"
                    ),
                    "auth-service": (
                        "Error rate: 94% | DB connection wait: 28s | "
                        "Active connections: 0 | Request queue: 847"
                    ),
                    "postgres-db": (
                        "Connections: 500/500 (100%) | Query queue: 847 | "
                        "CPU: 98% | Memory: 89% | Active queries: 500"
                    ),
                },
                "check_dependencies": {
                    "api-gateway": "Depends on: auth-service [CRITICAL], product-service [OK]",
                    "auth-service": "Depends on: postgres-db [CRITICAL], redis-session [OK]",
                    "postgres-db": "No upstream dependencies — root level service",
                },
                "check_recent_deploys": {
                    "api-gateway":  "Last deploy: 3 days ago — no recent changes",
                    "auth-service": (
                        "Last deploy: 47 min ago — PR #2341: "
                        "increased default connection pool size from 10 to 500"
                    ),
                    "postgres-db":  "Last deploy: 12 days ago — no recent changes",
                },
            },
            "correct_severity":    "P1",
            "adjacent_severities": ["P2"],
        },

        # AC-002: CDN cache invalidation storm → P2
        {
            "scenario_id": "AC-002",
            "description": (
                "CDN cache invalidation storm: a misconfigured purge cronjob wiped "
                "all 2.1M cached keys, sending 40× normal traffic to origin. "
                "Site degraded but not fully down — P2 severity."
            ),
            "incident_summary": (
                "P2 ALERT — CDN cache hit rate dropped from 94% to 3%, "
                "product-service origin traffic up 4000%, image-service CPU at 95%. "
                "Pages loading slowly (p99: 18s). Checkout still working."
            ),
            "alert": {
                "id":               "ALT-20240315-002",
                "title":            "HIGH: CDN cache miss storm — origin overloaded",
                "severity_fired":   "P2",
                "affected_services": ["cdn-edge", "product-service", "image-service"],
                "symptoms": [
                    "CDN cache hit rate: 3% (normal: 94%)",
                    "product-service: origin RPS 48,000 (normal: 1,200)",
                    "image-service: CPU 95%, p99 latency 18s",
                    "User experience: product pages slow, some images timing out",
                    "Checkout: still functional (not affected)",
                ],
                "error_rate":             0.15,
                "duration_minutes":        8,
                "revenue_impact_per_min":  800,
            },
            "known_services": {"cdn-edge", "product-service", "image-service"},
            "tool_responses": {
                "query_logs": {
                    "cdn-edge": (
                        "2024-03-15T10:22:00Z INFO cache MISS ratio: 97% (5min window)\n"
                        "2024-03-15T10:20:11Z WARN mass cache invalidation — "
                        "2,100,000 keys purged by purge-job-prod\n"
                        "2024-03-15T10:20:10Z INFO purge pattern: /* (ALL keys)"
                    ),
                    "product-service": (
                        "2024-03-15T10:22:05Z WARN request queue depth: 12,400\n"
                        "2024-03-15T10:22:06Z ERROR timeout fetching from image-service (18s)\n"
                        "2024-03-15T10:22:07Z WARN worker pool 95% utilized"
                    ),
                    "image-service": (
                        "2024-03-15T10:22:00Z WARN CPU throttling engaged (95%)\n"
                        "2024-03-15T10:22:01Z ERROR worker pool exhausted — dropping requests\n"
                        "2024-03-15T10:22:02Z ERROR OOM risk: memory at 91%"
                    ),
                },
                "check_metrics": {
                    "cdn-edge": (
                        "Cache hit rate: 3% | Purge events (1h): 1 mass purge | "
                        "Origin RPS: 48,000 | Bandwidth: 890 Gbps"
                    ),
                    "product-service": (
                        "Origin RPS: 48,000 (normal: 1,200) | "
                        "Queue depth: 12,400 | Worker utilization: 95%"
                    ),
                    "image-service": (
                        "CPU: 95% | Memory: 91% | "
                        "Worker pool: 0 free / 200 | p99 latency: 18s"
                    ),
                },
                "check_dependencies": {
                    "cdn-edge":       "Origin: product-service [OVERLOADED]",
                    "product-service": "Depends on: image-service [DEGRADED], postgres-db [OK]",
                    "image-service":   "Depends on: object-storage [OK] — no upstream issues",
                },
                "check_recent_deploys": {
                    "cdn-edge": (
                        "Cronjob purge-job-prod updated 2h ago — "
                        "purge pattern changed from /images/* to /* (all keys)"
                    ),
                    "product-service": "Last deploy: 5 days ago — no recent changes",
                    "image-service":   "Last deploy: 2 days ago — no recent changes",
                },
            },
            "correct_severity":    "P2",
            "adjacent_severities": ["P1", "P3"],
        },
    ],

    # ── TASK 2: ROOT CAUSE ANALYSIS ─────────────────────────────────────────

    "root_cause_analysis": [

        # RCA-001: Analytics service OOM kills postgres-db
        {
            "scenario_id": "RCA-001",
            "description": (
                "postgres-db was OOM-killed by the Linux kernel after a runaway "
                "analytics query with no LIMIT clause consumed all available memory. "
                "All downstream services are now failing. analytics-service is the culprit."
            ),
            "incident_summary": (
                "Multiple services down: api-gateway 503, auth-service failing, "
                "order-service write failures. postgres-db restarting in a loop. "
                "Root cause is upstream — trace the failure chain."
            ),
            "alert": {
                "id":              "ALT-RCA-001",
                "title":           "CRITICAL: postgres-db crash loop — all dependents down",
                "severity_fired":  "P1",
                "affected_services": [
                    "api-gateway", "auth-service", "order-service", "postgres-db",
                ],
                "symptoms": [
                    "postgres-db: 4 restarts in 12 minutes",
                    "auth-service: connection refused — 100% failure",
                    "order-service: all writes failing",
                    "api-gateway: 503 on all authenticated routes",
                    "analytics-service: last job failed 12 min ago",
                ],
                "error_rate":       0.95,
                "duration_minutes": 14,
            },
            "known_services": {
                "api-gateway", "auth-service", "order-service",
                "postgres-db", "analytics-service", "redis-session",
            },
            "tool_responses": {
                "query_logs": {
                    "postgres-db": (
                        "2024-03-16T02:11:00Z LOG database system shut down at 02:10:58\n"
                        "2024-03-16T02:10:58Z FATAL Out of Memory: Kill process 1847 (postgres) "
                        "score 982 or sacrifice child\n"
                        "2024-03-16T02:10:30Z LOG process 1847 query running 12min: "
                        "SELECT * FROM events JOIN user_sessions JOIN orders "
                        "JOIN products — no LIMIT clause, est 847M rows"
                    ),
                    "analytics-service": (
                        "2024-03-16T01:58:00Z INFO starting job: full_history_export\n"
                        "2024-03-16T01:58:01Z WARN query has no LIMIT — estimated 847M rows\n"
                        "2024-03-16T02:10:55Z ERROR job killed by OOM — full_history_export FAILED"
                    ),
                    "auth-service": (
                        "2024-03-16T02:11:05Z ERROR connect ECONNREFUSED postgres-db:5432\n"
                        "2024-03-16T02:11:06Z ERROR all retries exhausted — giving up"
                    ),
                    "api-gateway": (
                        "2024-03-16T02:11:10Z ERROR upstream auth-service: 503 Service Unavailable"
                    ),
                    "order-service": (
                        "2024-03-16T02:11:08Z ERROR pq: the database system is starting up"
                    ),
                    "redis-session": "No errors — operating normally at 99.2% hit rate",
                },
                "check_metrics": {
                    "postgres-db": (
                        "Memory: OOM killed (0% free at crash) | "
                        "Restarts: 4 in 12min | Status: RESTARTING"
                    ),
                    "analytics-service": (
                        "Memory at crash: 31.2GB / 32GB (97.5%) | "
                        "Job runtime: 12min 55s | Status: ERROR"
                    ),
                    "auth-service":  "Connection success: 0% | DB: CRITICAL | Redis: OK",
                    "api-gateway":   "503 rate: 95% | Auth dependency: DOWN",
                    "order-service": "Write success: 0% | DB: RESTARTING",
                    "redis-session": "Hit rate: 99.2% | Memory: 42% | Healthy",
                },
                "check_dependencies": {
                    "postgres-db": (
                        "Clients: auth-service, order-service, analytics-service, product-service"
                    ),
                    "analytics-service": "Depends on: postgres-db [CRASH LOOP]",
                    "auth-service":      "Depends on: postgres-db [CRASH LOOP], redis-session [OK]",
                    "api-gateway":       "Depends on: auth-service [DOWN]",
                    "order-service":     "Depends on: postgres-db [CRASH LOOP]",
                    "redis-session":     "No DB dependency — standalone cache",
                },
                "check_recent_deploys": {
                    "analytics-service": (
                        "Deploy 6h ago: added full_history_export scheduled job — "
                        "runs daily at 02:00 UTC, no LIMIT on cross-table JOIN"
                    ),
                    "postgres-db":   "No deploys in 3 weeks",
                    "auth-service":  "No recent deploys",
                    "order-service": "No recent deploys",
                    "redis-session": "No recent deploys",
                },
                "check_service_status": {
                    "postgres-db":       "RESTARTING | Uptime: 47s | Crash reason: OOM",
                    "analytics-service": "ERROR | Last job: full_history_export FAILED",
                    "auth-service":      "DOWN | Waiting for postgres-db",
                    "api-gateway":       "DEGRADED | 95% requests failing",
                    "order-service":     "DOWN | Waiting for postgres-db",
                    "redis-session":     "HEALTHY | All normal",
                },
            },
            "correct_root_cause": {
                "service":      "analytics-service",
                "failure_mode": "unbounded query OOM killing postgres-db",
            },
            "wrong_actions": {
                "restart_service:auth-service":  "auth-service is a victim — DB must be fixed first",
                "restart_service:api-gateway":   "api-gateway is downstream — won't help",
                "scale_service:postgres-db":     "Scaling won't prevent OOM if the bad query runs again",
                "rollback_deploy:postgres-db":   "postgres-db has no recent deploys",
            },
        },

        # RCA-002: BGP route withdrawal — AZ network partition
        {
            "scenario_id": "RCA-002",
            "description": (
                "A BGP route withdrawal isolated AZ-1 (where payment-service runs) "
                "from AZ-2 and AZ-3, causing 61% of checkout requests to fail. "
                "Services within AZ-1 are healthy — it is a pure network issue."
            ),
            "incident_summary": (
                "Checkout failure rate 61% — AZ-2 and AZ-3 cannot reach payment-service "
                "in AZ-1. AZ-1 users unaffected. fraud-detection-service also unreachable "
                "cross-AZ. Network infrastructure change 18 min ago."
            ),
            "alert": {
                "id":              "ALT-RCA-002",
                "title":           "HIGH: checkout failure 61% — cross-AZ connectivity loss",
                "severity_fired":  "P2",
                "affected_services": [
                    "order-service", "payment-service", "fraud-detection-service",
                ],
                "symptoms": [
                    "checkout failure rate: 61% (AZ-2/AZ-3 only)",
                    "payment-service: unreachable from AZ-2, AZ-3",
                    "fraud-detection-service: timeout from AZ-2, AZ-3",
                    "AZ-1 users: 0% failure rate",
                    "Network: AZ-2/AZ-3 → AZ-1 routing broken",
                ],
                "error_rate":       0.61,
                "duration_minutes": 9,
            },
            "known_services": {
                "order-service", "payment-service", "fraud-detection-service",
                "postgres-db", "redis-payment-cache", "network-infra",
            },
            "tool_responses": {
                "query_logs": {
                    "order-service": (
                        "2024-03-17T14:32:10Z ERROR connection timeout payment-service:8080 "
                        "(AZ-2 to AZ-1: no route to host)\n"
                        "2024-03-17T14:32:11Z ERROR fraud-detection-service: i/o timeout (30s)"
                    ),
                    "payment-service": (
                        "2024-03-17T14:31:58Z WARN health check from AZ-2 LB failing\n"
                        "2024-03-17T14:31:59Z INFO AZ-1 local traffic: all normal"
                    ),
                    "fraud-detection-service": (
                        "2024-03-17T14:32:00Z INFO AZ-1 requests: all normal\n"
                        "2024-03-17T14:32:01Z WARN cross-AZ health probes: 100% timeout"
                    ),
                    "network-infra": (
                        "2024-03-17T14:31:45Z CRITICAL BGP peer 10.0.2.1 route withdrawal — "
                        "AZ-2 lost route to AZ-1 CIDR 10.0.1.0/24\n"
                        "2024-03-17T14:31:45Z CRITICAL BGP peer 10.0.3.1 route withdrawal — "
                        "AZ-3 lost route to AZ-1 CIDR 10.0.1.0/24\n"
                        "2024-03-17T14:31:44Z INFO router config change applied — "
                        "BGP advertisement policy updated"
                    ),
                    "postgres-db":        "Operating normally — no errors detected",
                    "redis-payment-cache": "Operating normally — AZ-1 traffic only, all healthy",
                },
                "check_metrics": {
                    "order-service": (
                        "AZ-2 checkout failure: 99% | AZ-3 checkout failure: 98% | "
                        "AZ-1 checkout failure: 0.2% (baseline)"
                    ),
                    "payment-service": (
                        "AZ-1 traffic: normal (100% success) | "
                        "AZ-2/AZ-3 inbound connections: 0 (blocked)"
                    ),
                    "fraud-detection-service": (
                        "AZ-1 processing: normal | "
                        "Cross-AZ health checks: 100% timeout"
                    ),
                    "network-infra": (
                        "BGP session AZ-2: WITHDRAWN | BGP session AZ-3: WITHDRAWN | "
                        "AZ-1 internal: all UP | Config change: 18min ago"
                    ),
                    "postgres-db":         "All metrics normal — no anomalies",
                    "redis-payment-cache": "All metrics normal — AZ-1 only traffic",
                },
                "check_dependencies": {
                    "order-service": (
                        "Depends on: payment-service [PARTITIONED], "
                        "fraud-detection-service [PARTITIONED]"
                    ),
                    "payment-service":         "Depends on: postgres-db [OK], redis-payment-cache [OK]",
                    "fraud-detection-service": "Depends on: postgres-db [OK]",
                    "network-infra":           "BGP peers: AZ-2 [WITHDRAWN], AZ-3 [WITHDRAWN], AZ-1 [UP]",
                },
                "check_recent_deploys": {
                    "network-infra": (
                        "Router config change 18min ago — BGP route advertisement policy update: "
                        "inadvertently withdrew AZ-1 routes from AZ-2/AZ-3 peers"
                    ),
                    "payment-service":         "No recent deploys",
                    "order-service":           "No recent deploys",
                    "fraud-detection-service": "No recent deploys",
                },
                "check_service_status": {
                    "payment-service":         "HEALTHY within AZ-1 | Cross-AZ: UNREACHABLE",
                    "order-service":           "DEGRADED | AZ-2/AZ-3 instances failing",
                    "network-infra":           "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN | AZ-1: UP",
                    "fraud-detection-service": "HEALTHY within AZ-1 | Cross-AZ: UNREACHABLE",
                    "postgres-db":             "HEALTHY",
                    "redis-payment-cache":     "HEALTHY",
                },
            },
            "correct_root_cause": {
                "service":      "network-infra",
                "failure_mode": "BGP route withdrawal causing AZ network partition",
            },
            "wrong_actions": {
                "restart_service:payment-service":  "payment-service is healthy — restarting won't fix routing",
                "restart_service:order-service":    "order-service is a victim of the partition",
                "scale_service:payment-service":    "Scaling won't fix a BGP routing issue",
                "clear_cache:redis-payment-cache":  "Cache is healthy — not the cause",
            },
        },
    ],

    # ── TASK 3: REMEDIATION PLANNING ────────────────────────────────────────

    "remediation_planning": [

        # RP-001: Full OOM remediation — disable cron, restart cascade
        {
            "scenario_id": "RP-001",
            "description": (
                "Full remediation: analytics-service OOM-killed postgres-db with an "
                "unbounded query. Must disable the offending job, restart postgres, "
                "restore all downstream services, and document the resolution."
            ),
            "incident_summary": (
                "CRITICAL — postgres-db in OOM crash loop. auth-service, order-service, "
                "api-gateway all down. analytics-service caused it with unbounded query. "
                "Required actions: disable job, restart postgres, restore services, document."
            ),
            "alert": {
                "id":              "ALT-RP-001",
                "title":           "CRITICAL: postgres-db OOM crash loop — full stack down",
                "severity_fired":  "P1",
                "affected_services": [
                    "postgres-db", "analytics-service",
                    "auth-service", "order-service", "api-gateway",
                ],
            },
            "known_services": {
                "postgres-db", "auth-service", "order-service",
                "api-gateway", "analytics-service",
            },
            "tool_responses": {
                "query_logs": {
                    "postgres-db": (
                        "FATAL: Out of Memory: Kill process (postgres) — "
                        "analytics query running 12min with no LIMIT"
                    ),
                    "analytics-service": (
                        "ERROR: full_history_export — unbounded JOIN, 847M rows, killed by OOM"
                    ),
                    "auth-service":  "ERROR: connect ECONNREFUSED postgres-db:5432",
                    "order-service": "ERROR: pq: the database system is starting up",
                    "api-gateway":   "ERROR: upstream auth-service 503",
                },
                "check_metrics": {
                    "postgres-db":       "Memory: OOM | Restarts: 4 | Status: CRASH LOOP",
                    "analytics-service": "Memory spike: 31GB/32GB | Status: ERROR",
                    "auth-service":      "Connection success: 0% | Waiting for DB",
                    "order-service":     "Write success: 0% | Waiting for DB",
                    "api-gateway":       "503 rate: 95% | Auth: DOWN",
                },
                "check_dependencies": {
                    "postgres-db":       "Clients: auth-service, order-service, analytics-service",
                    "analytics-service": "Depends on: postgres-db [CRASH LOOP]",
                    "auth-service":      "Depends on: postgres-db [CRASH LOOP]",
                    "order-service":     "Depends on: postgres-db [CRASH LOOP]",
                },
                "check_recent_deploys": {
                    "analytics-service": (
                        "Deploy 6h ago: full_history_export job — "
                        "unbounded cross-table JOIN query"
                    ),
                    "postgres-db": "No recent changes",
                },
                "check_service_status": {
                    "postgres-db":       "CRASH LOOP | OOM kill | Uptime: 47s",
                    "analytics-service": "ERROR | Last job failed",
                    "auth-service":      "DOWN",
                    "order-service":     "DOWN",
                    "api-gateway":       "DEGRADED",
                },
            },
            "remediation_data": {
                "disable_feature_flag": {
                    "full_history_export": (
                        "Cron job full_history_export DISABLED — "
                        "no more unbounded queries will run"
                    ),
                },
                "restart_service": {
                    "postgres-db": (
                        "postgres-db restarted cleanly — "
                        "accepting connections (12/500 active)"
                    ),
                    "analytics-service": (
                        "analytics-service restarted — no active queries"
                    ),
                    "auth-service":  "auth-service restarted — reconnected to postgres-db OK",
                    "order-service": "order-service restarted — writes resuming normally",
                },
                "execute_runbook_step": {
                    "verify_db_health": (
                        "postgres-db: connections 12/500, CPU 12%, Memory 34% — healthy"
                    ),
                    "check_service_recovery": (
                        "auth-service OK | order-service OK | api-gateway OK"
                    ),
                },
            },
            "correct_remediation_sequence": [
                "disable_feature_flag:full_history_export",
                "restart_service:analytics-service",
                "restart_service:postgres-db",
                "restart_service:auth-service",
                "restart_service:order-service",
            ],
            "wrong_actions": {
                "rollback_deploy:postgres-db": (
                    "postgres-db has no recent deploy to roll back"
                ),
                "scale_service:postgres-db": (
                    "Scaling won't prevent the OOM query from running again"
                ),
                "restart_service:api-gateway": (
                    "api-gateway is downstream — fix the DB first"
                ),
            },
            "resolution_keywords": [
                "analytics", "oom", "memory", "postgres", "query",
                "full_history_export", "disabled", "restarted", "recovered",
            ],
        },

        # RP-002: Full BGP remediation — restore routes, rollback config, verify
        {
            "scenario_id": "RP-002",
            "description": (
                "Full remediation: BGP route withdrawal partitioned AZ-2/AZ-3 from "
                "AZ-1 where payment-service runs. Must restore BGP routes, roll back "
                "the router config change, verify checkout recovery, and document."
            ),
            "incident_summary": (
                "P2 — BGP partition isolating payment-service from 61% of users. "
                "Router config change 18min ago is the cause. "
                "Required: restore BGP routes, rollback network config, verify recovery."
            ),
            "alert": {
                "id":              "ALT-RP-002",
                "title":           "HIGH: checkout 61% failure — BGP AZ partition",
                "severity_fired":  "P2",
                "affected_services": ["network-infra", "order-service", "payment-service"],
            },
            "known_services": {
                "network-infra", "order-service", "payment-service",
                "fraud-detection-service", "postgres-db",
            },
            "tool_responses": {
                "query_logs": {
                    "network-infra": (
                        "CRITICAL: BGP route withdrawal — "
                        "AZ-2/AZ-3 lost route to AZ-1 10.0.1.0/24\n"
                        "Router config change 18min ago: BGP policy updated"
                    ),
                    "order-service": (
                        "ERROR: connection timeout payment-service — no route to host"
                    ),
                    "payment-service": (
                        "INFO: AZ-1 traffic normal | "
                        "WARN: cross-AZ health checks failing"
                    ),
                    "fraud-detection-service": (
                        "WARN: cross-AZ health probes 100% timeout | AZ-1 traffic: normal"
                    ),
                    "postgres-db": "Operating normally",
                },
                "check_metrics": {
                    "network-infra":  "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN | AZ-1: UP",
                    "order-service":  "AZ-2 failure: 99% | AZ-1 failure: 0.2%",
                    "payment-service": "AZ-1: normal | Cross-AZ inbound: 0",
                    "fraud-detection-service": "AZ-1: normal | Cross-AZ: 0",
                    "postgres-db":    "All normal",
                },
                "check_dependencies": {
                    "order-service":  "Depends on: payment-service [PARTITIONED]",
                    "payment-service": "Depends on: postgres-db [OK]",
                    "network-infra":  "BGP peers: AZ-2 [WITHDRAWN], AZ-3 [WITHDRAWN]",
                },
                "check_recent_deploys": {
                    "network-infra": (
                        "Config change 18min ago — BGP policy update "
                        "accidentally withdrew AZ-1 routes"
                    ),
                    "payment-service": "No recent deploys",
                    "order-service":   "No recent deploys",
                },
                "check_service_status": {
                    "network-infra":   "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN",
                    "payment-service": "HEALTHY (AZ-1) | Cross-AZ: UNREACHABLE",
                    "order-service":   "DEGRADED",
                },
            },
            "remediation_data": {
                "rollback_deploy": {
                    "network-infra": (
                        "Router config rolled back — "
                        "BGP advertisement policy restored to previous version"
                    ),
                },
                "execute_runbook_step": {
                    "restore_bgp_routes": (
                        "BGP routes restored — AZ-2/AZ-3 can now reach AZ-1 10.0.1.0/24"
                    ),
                    "verify_checkout_recovery": (
                        "Checkout failure rate: 0.3% — incident fully resolved"
                    ),
                },
            },
            "correct_remediation_sequence": [
                "execute_runbook_step:restore_bgp_routes",
                "rollback_deploy:network-infra",
                "execute_runbook_step:verify_checkout_recovery",
            ],
            "wrong_actions": {
                "restart_service:payment-service":  "payment-service is healthy — network is the issue",
                "scale_service:payment-service":    "Scaling won't fix BGP routing",
                "restart_service:order-service":    "order-service is a victim",
                "clear_cache":                      "Cache is unrelated to network routing",
            },
            "resolution_keywords": [
                "bgp", "network", "route", "rollback", "partition",
                "restored", "az-1", "az-2", "az-3", "checkout", "withdrawal",
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_task(task_id: str) -> dict:
    if task_id not in ALL_TASKS:
        raise ValueError(
            f"Unknown task_id '{task_id}'. "
            f"Valid: {list(ALL_TASKS.keys())}"
        )
    return ALL_TASKS[task_id]


def get_scenario(task_id: str, index: int) -> dict:
    if task_id not in SCENARIOS:
        raise ValueError(f"No scenarios for task_id '{task_id}'.")
    scenarios = SCENARIOS[task_id]
    if index < 0 or index >= len(scenarios):
        raise ValueError(
            f"Scenario index {index} out of range for task '{task_id}' "
            f"(valid: 0–{len(scenarios) - 1})"
        )
    return scenarios[index]


def list_tasks() -> list:
    return list(ALL_TASKS.values())