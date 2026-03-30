"""
tasks.py — Task definitions and scenario data for SRE Incident Response OpenEnv.

Structure:
  ALL_TASKS  : dict[task_id -> task metadata]
  SCENARIOS  : dict[task_id -> list[scenario_dict]]

Public API:
  get_task(task_id)              -> task metadata dict
  get_scenario(task_id, index)   -> scenario dict
  list_tasks()                   -> list of task metadata dicts
"""

ALL_TASKS: dict = {
    "alert_classification": {
        "id": "alert_classification",
        "name": "Task 1: Alert Severity Classification",
        "difficulty": "easy",
        "max_steps": 3,
        "score_range": [0.0, 1.0],
        "description": (
            "Given an incoming alert with symptoms, affected services, and error rates, "
            "classify the incident severity as P1 (CRITICAL), P2 (HIGH), P3 (MEDIUM), "
            "or P4 (LOW). Use available diagnostic tools to gather evidence before submitting."
        ),
        "available_actions": [
            "query_logs", "check_metrics", "check_dependencies",
            "check_recent_deploys", "submit_severity",
        ],
        "submission_action": "submit_severity",
    },
    "root_cause_analysis": {
        "id": "root_cause_analysis",
        "name": "Task 2: Root Cause Analysis",
        "difficulty": "medium",
        "max_steps": 10,
        "score_range": [0.0, 1.0],
        "description": (
            "An active incident is in progress. Use diagnostic tools to query logs, "
            "metrics, dependencies, and recent deploys across services. Identify the "
            "exact root cause service and failure mode, then submit your findings."
        ),
        "available_actions": [
            "query_logs", "check_metrics", "check_dependencies",
            "check_recent_deploys", "check_service_status", "submit_root_cause",
        ],
        "submission_action": "submit_root_cause",
    },
    "remediation_planning": {
        "id": "remediation_planning",
        "name": "Task 3: Incident Remediation",
        "difficulty": "hard",
        "max_steps": 15,
        "score_range": [0.0, 1.0],
        "description": (
            "A production incident requires full resolution. Diagnose the root cause, "
            "execute the correct remediation sequence (restart, rollback, scale, drain), "
            "then submit a resolution summary. Scored on investigation quality, "
            "remediation correctness, efficiency, and documentation."
        ),
        "available_actions": [
            "query_logs", "check_metrics", "check_dependencies",
            "check_recent_deploys", "check_service_status",
            "restart_service", "rollback_deploy", "scale_service",
            "disable_feature_flag", "clear_cache", "execute_runbook_step",
            "submit_resolution",
        ],
        "submission_action": "submit_resolution",
    },
}

# ---------------------------------------------------------------------------
# Scenario data
# Each scenario has:
#   scenario_id, description, incident_summary, alert, known_services,
#   tool_responses, correct_severity, correct_root_cause, correct_remediation,
#   wrong_actions
# ---------------------------------------------------------------------------

SCENARIOS: dict = {

    # ── ALERT CLASSIFICATION ─────────────────────────────────────────────────

    "alert_classification": [

        # Scenario 0: DB connection pool exhaustion cascading up
        {
            "scenario_id": "AC-001",
            "description": (
                "Cascading failure: postgres-db connection pool exhausted, "
                "causing auth-service timeouts, which is blocking api-gateway requests."
            ),
            "incident_summary": (
                "P1 ALERT — api-gateway 5xx rate 78%, auth-service timeout rate 94%, "
                "postgres-db connection pool at 100% (500/500). "
                "Checkout flow completely down. Revenue impact: $12k/min."
            ),
            "alert": {
                "id": "ALT-20240315-001",
                "title": "CRITICAL: api-gateway error rate 78%",
                "severity_fired": "P1",
                "affected_services": ["api-gateway", "auth-service", "postgres-db"],
                "symptoms": [
                    "api-gateway: HTTP 503 rate 78% (up from baseline 0.1%)",
                    "auth-service: connection timeout 94% of requests",
                    "postgres-db: connection pool 500/500 (100% utilized)",
                    "checkout flow: completely unavailable",
                    "Active user sessions: 0 new logins succeeding",
                ],
                "error_rate": 0.78,
                "duration_minutes": 4,
                "revenue_impact_per_min": 12000,
            },
            "known_services": {"api-gateway", "auth-service", "postgres-db"},
            "tool_responses": {
                "query_logs": {
                    "api-gateway": (
                        "2024-03-15T10:04:12Z ERROR upstream connect error or disconnect/reset "
                        "before headers. reset reason: connection timeout — auth-service:8080\n"
                        "2024-03-15T10:04:13Z ERROR 503 Service Unavailable — upstream: auth-service"
                    ),
                    "auth-service": (
                        "2024-03-15T10:04:10Z ERROR pq: sorry, too many clients already\n"
                        "2024-03-15T10:04:11Z ERROR dial tcp postgres-db:5432: connect: "
                        "connection refused — pool exhausted"
                    ),
                    "postgres-db": (
                        "2024-03-15T10:03:58Z LOG connection received: host=auth-service\n"
                        "2024-03-15T10:04:00Z FATAL remaining connection slots are reserved "
                        "for non-replication superuser connections\n"
                        "2024-03-15T10:04:01Z LOG max_connections=500 currently active=500"
                    ),
                },
                "check_metrics": {
                    "api-gateway": "HTTP 5xx rate: 78% | Latency p99: 30s (timeout) | RPS: 1200",
                    "auth-service": "Error rate: 94% | DB connection wait: 28s | Active conns: 0",
                    "postgres-db": "Connections: 500/500 (100%) | Query queue depth: 847 | CPU: 98%",
                },
                "check_dependencies": {
                    "api-gateway": "Depends on: auth-service [DEGRADED], product-service [OK]",
                    "auth-service": "Depends on: postgres-db [CRITICAL], redis-session [OK]",
                    "postgres-db": "No upstream dependencies",
                },
                "check_recent_deploys": {
                    "api-gateway": "Last deploy: 3 days ago — no recent changes",
                    "auth-service": "Last deploy: 47 mins ago — added connection pool monitoring",
                    "postgres-db": "Last deploy: 12 days ago — no recent changes",
                },
            },
            "correct_severity": "P1",
            "adjacent_severities": ["P2"],
            "correct_root_cause": {
                "service": "postgres-db",
                "failure_mode": "connection pool exhaustion",
            },
            "correct_remediation": [
                "restart_service:auth-service",
                "execute_runbook_step:increase_max_connections",
                "scale_service:postgres-db",
            ],
            "wrong_actions": {
                "rollback_deploy": "Rolling back auth-service monitoring changes won't fix pool exhaustion",
                "restart_service:api-gateway": "api-gateway is a victim, not the cause",
                "clear_cache": "Cache is not related to DB connection pool exhaustion",
            },
        },

        # Scenario 1: CDN cache invalidation storm
        {
            "scenario_id": "AC-002",
            "description": (
                "CDN cache invalidation storm: a misconfigured cache purge script ran "
                "against all product images, sending 40x normal traffic to origin."
            ),
            "incident_summary": (
                "P2 ALERT — product-service origin traffic spike 4000%, "
                "image-service CPU 95%, CDN cache hit rate dropped from 94% to 3%. "
                "Site slow but partially functional. Latency p99: 18s."
            ),
            "alert": {
                "id": "ALT-20240315-002",
                "title": "HIGH: product-service origin traffic anomaly",
                "severity_fired": "P2",
                "affected_services": ["cdn-edge", "product-service", "image-service"],
                "symptoms": [
                    "CDN cache hit rate: 3% (normal: 94%)",
                    "product-service: origin RPS 48,000 (normal: 1,200)",
                    "image-service: CPU 95%, latency p99 18s",
                    "User-facing: product pages loading slowly, some images timing out",
                    "No complete outage — checkout still working",
                ],
                "error_rate": 0.15,
                "duration_minutes": 8,
                "revenue_impact_per_min": 800,
            },
            "known_services": {"cdn-edge", "product-service", "image-service"},
            "tool_responses": {
                "query_logs": {
                    "cdn-edge": (
                        "2024-03-15T10:22:00Z INFO cache MISS ratio: 97% (last 5min)\n"
                        "2024-03-15T10:20:11Z WARN mass cache invalidation event detected "
                        "— 2.1M keys purged by purge-job-prod\n"
                        "2024-03-15T10:20:10Z INFO purge request from 10.0.1.45 — pattern: /*"
                    ),
                    "product-service": (
                        "2024-03-15T10:22:05Z WARN request queue depth: 12,400\n"
                        "2024-03-15T10:22:06Z ERROR timeout fetching image from image-service"
                    ),
                    "image-service": (
                        "2024-03-15T10:22:00Z WARN CPU throttling engaged\n"
                        "2024-03-15T10:22:01Z ERROR worker pool exhausted — dropping requests"
                    ),
                },
                "check_metrics": {
                    "cdn-edge": "Cache hit rate: 3% | Purge events last hour: 1 (mass) | Origin RPS: 48k",
                    "product-service": "Origin RPS: 48,000 (normal 1,200) | Queue depth: 12,400",
                    "image-service": "CPU: 95% | Worker pool: 0 free / 200 | Latency p99: 18s",
                },
                "check_dependencies": {
                    "cdn-edge": "Origin: product-service [OVERLOADED]",
                    "product-service": "Depends on: image-service [DEGRADED], postgres-db [OK]",
                    "image-service": "Depends on: object-storage [OK] — no upstream issues",
                },
                "check_recent_deploys": {
                    "cdn-edge": "Cronjob purge-job-prod modified 2 hours ago — pattern changed from /images/* to /*",
                    "product-service": "Last deploy: 5 days ago",
                    "image-service": "Last deploy: 2 days ago",
                },
            },
            "correct_severity": "P2",
            "adjacent_severities": ["P1", "P3"],
            "correct_root_cause": {
                "service": "cdn-edge",
                "failure_mode": "mass cache invalidation / misconfigured purge job",
            },
            "correct_remediation": [
                "disable_feature_flag:purge-job-prod",
                "execute_runbook_step:warm_cdn_cache",
                "scale_service:image-service",
            ],
            "wrong_actions": {
                "restart_service:image-service": "Restarting won't fix the CDN cache miss storm at source",
                "rollback_deploy:product-service": "product-service has no recent changes",
                "restart_service:cdn-edge": "Restarting CDN edge nodes will make cache miss rate worse temporarily",
            },
        },
    ],

    # ── ROOT CAUSE ANALYSIS ──────────────────────────────────────────────────

    "root_cause_analysis": [

        # Scenario 0: Postgres OOM killed by runaway analytics query
        {
            "scenario_id": "RCA-001",
            "description": (
                "postgres-db was OOM-killed by the Linux kernel after a runaway analytics "
                "query consumed all available memory, taking down all dependent services."
            ),
            "incident_summary": (
                "Multiple services down: api-gateway 503, auth-service failing, "
                "order-service unable to write. postgres-db restarting repeatedly. "
                "Root cause is upstream — needs investigation."
            ),
            "alert": {
                "id": "ALT-RCA-001",
                "title": "CRITICAL: postgres-db repeated restarts, all dependents degraded",
                "severity_fired": "P1",
                "affected_services": ["api-gateway", "auth-service", "order-service", "postgres-db"],
                "symptoms": [
                    "postgres-db: restarted 4 times in 12 minutes",
                    "auth-service: connection refused errors 100%",
                    "order-service: write failures 100%",
                    "api-gateway: 503 on all authenticated routes",
                ],
                "error_rate": 0.95,
                "duration_minutes": 14,
            },
            "known_services": {
                "api-gateway", "auth-service", "order-service",
                "postgres-db", "analytics-service", "redis-session",
            },
            "tool_responses": {
                "query_logs": {
                    "postgres-db": (
                        "2024-03-16T02:11:00Z LOG database system was shut down at 2024-03-16 02:10:58\n"
                        "2024-03-16T02:10:58Z FATAL Out of Memory: Kill process 1847 (postgres) "
                        "score 982 or sacrifice child\n"
                        "2024-03-16T02:10:30Z LOG process 1847 still running query started "
                        "2024-03-16 01:58:00: SELECT * FROM events JOIN user_sessions JOIN orders "
                        "JOIN products — no LIMIT clause"
                    ),
                    "analytics-service": (
                        "2024-03-16T01:58:00Z INFO starting scheduled report: full_history_export\n"
                        "2024-03-16T02:10:55Z ERROR query killed by OOM — report failed\n"
                        "2024-03-16T01:58:01Z WARN query has no LIMIT — estimated rows: 847M"
                    ),
                    "auth-service": (
                        "2024-03-16T02:11:05Z ERROR connect ECONNREFUSED postgres-db:5432\n"
                        "2024-03-16T02:11:06Z ERROR all retries exhausted"
                    ),
                    "api-gateway": (
                        "2024-03-16T02:11:10Z ERROR upstream auth-service: 503 Service Unavailable"
                    ),
                    "order-service": (
                        "2024-03-16T02:11:08Z ERROR pq: the database system is starting up"
                    ),
                    "redis-session": "No errors — operating normally",
                },
                "check_metrics": {
                    "postgres-db": "Memory: 0% free (OOM killed) | Restarts: 4 | Last crash: 2min ago",
                    "analytics-service": "Memory used: 31GB / 32GB at time of crash | Query runtime: 12min",
                    "auth-service": "Connection success rate: 0% | DB dependency: CRITICAL",
                    "api-gateway": "503 rate: 95% | Auth dependency: DOWN",
                    "order-service": "Write success rate: 0% | DB dependency: RESTARTING",
                    "redis-session": "Hit rate: 99.2% | Memory: 42% | All normal",
                },
                "check_dependencies": {
                    "postgres-db": "Clients: auth-service, order-service, analytics-service, product-service",
                    "analytics-service": "Depends on: postgres-db [RESTARTING]",
                    "auth-service": "Depends on: postgres-db [RESTARTING], redis-session [OK]",
                    "api-gateway": "Depends on: auth-service [DOWN]",
                    "order-service": "Depends on: postgres-db [RESTARTING]",
                    "redis-session": "No DB dependency — standalone",
                },
                "check_recent_deploys": {
                    "analytics-service": (
                        "Deploy 6 hours ago: added full_history_export scheduled job — "
                        "no LIMIT on cross-table JOIN query, runs at 02:00 UTC daily"
                    ),
                    "postgres-db": "No recent deploys — last change 3 weeks ago",
                    "auth-service": "No recent deploys",
                    "order-service": "No recent deploys",
                },
                "check_service_status": {
                    "postgres-db": "Status: RESTARTING | Uptime: 47s | Previous uptime: 14min",
                    "analytics-service": "Status: ERROR | Last job: full_history_export FAILED",
                    "auth-service": "Status: DOWN | Waiting for postgres-db",
                    "api-gateway": "Status: DEGRADED | 95% requests failing",
                },
            },
            "correct_root_cause": {
                "service": "analytics-service",
                "failure_mode": "unbounded query causing OOM kill on postgres-db",
            },
            "correct_remediation": [
                "restart_service:analytics-service",
                "disable_feature_flag:full_history_export",
                "execute_runbook_step:restart_postgres",
            ],
            "wrong_actions": {
                "restart_service:auth-service": "auth-service is a victim, restarting won't fix the DB",
                "restart_service:api-gateway": "api-gateway is a victim downstream",
                "scale_service:postgres-db": "Scaling DB won't prevent OOM if the bad query runs again",
                "rollback_deploy:postgres-db": "postgres-db has no recent deploys",
            },
        },

        # Scenario 1: Network partition isolating payment service
        {
            "scenario_id": "RCA-002",
            "description": (
                "A BGP route withdrawal caused a network partition isolating the "
                "payment-service AZ, resulting in 61% checkout failure rate."
            ),
            "incident_summary": (
                "Checkout failures 61%, payment-service unreachable from AZ-2 and AZ-3. "
                "fraud-detection-service also unreachable. "
                "Partial service — users in AZ-1 unaffected."
            ),
            "alert": {
                "id": "ALT-RCA-002",
                "title": "HIGH: checkout failure rate 61%, payment-service connectivity loss",
                "severity_fired": "P2",
                "affected_services": ["order-service", "payment-service", "fraud-detection-service"],
                "symptoms": [
                    "checkout failure rate: 61% (only AZ-2 and AZ-3 affected)",
                    "payment-service: unreachable from AZ-2, AZ-3",
                    "fraud-detection-service: timeout from AZ-2, AZ-3",
                    "AZ-1 users: completely unaffected",
                    "Network latency AZ-2→AZ-1: infinite (no route)",
                ],
                "error_rate": 0.61,
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
                        "(AZ-2 → AZ-1: no route to host)\n"
                        "2024-03-17T14:32:11Z ERROR fraud-detection-service: i/o timeout"
                    ),
                    "payment-service": (
                        "2024-03-17T14:31:58Z WARN health check failing from AZ-2 load balancer\n"
                        "2024-03-17T14:31:59Z INFO all local (AZ-1) requests processing normally"
                    ),
                    "fraud-detection-service": (
                        "2024-03-17T14:32:00Z INFO processing normally within AZ-1\n"
                        "2024-03-17T14:32:01Z WARN cross-AZ health checks timing out"
                    ),
                    "network-infra": (
                        "2024-03-17T14:31:45Z CRITICAL BGP peer 10.0.2.1 route withdrawal — "
                        "AZ-2 lost route to AZ-1 CIDR 10.0.1.0/24\n"
                        "2024-03-17T14:31:45Z CRITICAL BGP peer 10.0.3.1 route withdrawal — "
                        "AZ-3 lost route to AZ-1 CIDR 10.0.1.0/24"
                    ),
                    "postgres-db": "Operating normally — no errors",
                    "redis-payment-cache": "Operating normally — AZ-1 only traffic, all good",
                },
                "check_metrics": {
                    "order-service": "AZ-2 checkout failure: 99% | AZ-1 checkout failure: 0.2% (baseline)",
                    "payment-service": "AZ-1 traffic: normal | AZ-2/AZ-3 inbound: 0 (blocked by network)",
                    "fraud-detection-service": "AZ-1 normal | Cross-AZ: 100% timeout",
                    "network-infra": "BGP sessions AZ-2/AZ-3: DOWN | AZ-1 internal: all UP",
                    "postgres-db": "All metrics normal",
                    "redis-payment-cache": "All metrics normal",
                },
                "check_dependencies": {
                    "order-service": "Depends on: payment-service [PARTITIONED], fraud-detection-service [PARTITIONED]",
                    "payment-service": "Depends on: postgres-db [OK], redis-payment-cache [OK]",
                    "fraud-detection-service": "Depends on: postgres-db [OK]",
                    "network-infra": "BGP peers: AZ-2 [DOWN], AZ-3 [DOWN], AZ-1 [UP]",
                },
                "check_recent_deploys": {
                    "network-infra": (
                        "Router config change 18 mins ago: updated BGP route advertisement policy — "
                        "inadvertently withdrew AZ-1 routes from AZ-2/AZ-3 peers"
                    ),
                    "payment-service": "No recent deploys",
                    "order-service": "No recent deploys",
                },
                "check_service_status": {
                    "payment-service": "Status: HEALTHY (within AZ-1) | Cross-AZ: UNREACHABLE",
                    "order-service": "Status: DEGRADED | AZ-2/3 instances failing",
                    "network-infra": "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN | AZ-1: UP",
                    "fraud-detection-service": "Status: HEALTHY (within AZ-1) | Cross-AZ: UNREACHABLE",
                },
            },
            "correct_root_cause": {
                "service": "network-infra",
                "failure_mode": "BGP route withdrawal causing AZ network partition",
            },
            "correct_remediation": [
                "execute_runbook_step:restore_bgp_routes",
                "rollback_deploy:network-infra",
            ],
            "wrong_actions": {
                "restart_service:payment-service": "payment-service is healthy — network is the issue",
                "restart_service:order-service": "order-service is a victim of the network partition",
                "scale_service:payment-service": "Scaling won't fix a network routing problem",
                "clear_cache:redis-payment-cache": "Cache is operating normally — not the cause",
            },
        },
    ],

    # ── REMEDIATION PLANNING ─────────────────────────────────────────────────

    "remediation_planning": [

        # Scenario 0: Postgres OOM — full remediation required
        {
            "scenario_id": "RP-001",
            "description": (
                "Full remediation required: analytics-service OOM-killed postgres-db. "
                "Must stop the offending job, restart DB, restore services, document."
            ),
            "incident_summary": (
                "CRITICAL — postgres-db repeatedly OOM-killed by analytics runaway query. "
                "auth-service, order-service, api-gateway all down. "
                "Requires: stop analytics job, restart postgres, verify service recovery, document."
            ),
            "alert": {
                "id": "ALT-RP-001",
                "title": "CRITICAL: postgres-db OOM killed — full stack down",
                "severity_fired": "P1",
                "affected_services": ["postgres-db", "auth-service", "order-service", "api-gateway"],
            },
            "known_services": {
                "postgres-db", "auth-service", "order-service",
                "api-gateway", "analytics-service",
            },
            "tool_responses": {
                "query_logs": {
                    "postgres-db": (
                        "FATAL: Out of Memory: Kill process (postgres) — analytics query running 12min with no LIMIT"
                    ),
                    "analytics-service": "ERROR: full_history_export job — unbounded JOIN query killed by OOM",
                    "auth-service": "ERROR: connect ECONNREFUSED postgres-db:5432",
                    "order-service": "ERROR: pq: the database system is starting up",
                    "api-gateway": "ERROR: upstream auth-service 503",
                },
                "check_metrics": {
                    "postgres-db": "Memory: OOM | Restarts: 4 | Status: RESTARTING",
                    "analytics-service": "Status: ERROR | Memory spike to 31GB before crash",
                    "auth-service": "Connection success: 0% | Waiting for DB",
                    "order-service": "Write success: 0% | Waiting for DB",
                },
                "check_dependencies": {
                    "postgres-db": "Clients: auth-service, order-service, analytics-service",
                    "analytics-service": "Depends on: postgres-db",
                    "auth-service": "Depends on: postgres-db [DOWN]",
                    "order-service": "Depends on: postgres-db [DOWN]",
                },
                "check_recent_deploys": {
                    "analytics-service": "Deploy 6h ago: added full_history_export cron job — unbounded query",
                    "postgres-db": "No recent changes",
                },
                "check_service_status": {
                    "postgres-db": "RESTARTING | Uptime: 47s",
                    "analytics-service": "ERROR | Last job failed",
                    "auth-service": "DOWN",
                    "order-service": "DOWN",
                },
            },
            "remediation_data": {
                "disable_feature_flag": {
                    "full_history_export": "Cron job full_history_export disabled — analytics queries halted",
                },
                "restart_service": {
                    "postgres-db": "postgres-db restarted cleanly — accepting connections",
                    "analytics-service": "analytics-service restarted — no active queries",
                    "auth-service": "auth-service restarted — reconnected to postgres-db successfully",
                    "order-service": "order-service restarted — write operations resuming",
                },
                "execute_runbook_step": {
                    "verify_db_health": "postgres-db connections: 12/500 — healthy",
                    "check_service_recovery": "auth-service OK, order-service OK, api-gateway OK",
                },
            },
            "correct_severity": "P1",
            "correct_root_cause": {
                "service": "analytics-service",
                "failure_mode": "unbounded query OOM killing postgres-db",
            },
            "correct_remediation_sequence": [
                "disable_feature_flag:full_history_export",
                "restart_service:analytics-service",
                "restart_service:postgres-db",
                "restart_service:auth-service",
                "restart_service:order-service",
            ],
            "wrong_actions": {
                "rollback_deploy:postgres-db": "postgres-db has no recent deploy to roll back",
                "scale_service:postgres-db": "Scaling won't stop the OOM query from running again",
                "restart_service:api-gateway": "api-gateway is downstream victim — fix DB first",
            },
            "resolution_keywords": [
                "analytics", "oom", "memory", "postgres", "query", "full_history_export",
                "disabled", "restarted", "recovered",
            ],
        },

        # Scenario 1: BGP network partition — full remediation
        {
            "scenario_id": "RP-002",
            "description": (
                "Full remediation: BGP route withdrawal partitioned AZ-2/AZ-3 from AZ-1 "
                "where payment-service runs. Must restore BGP routes, roll back network config."
            ),
            "incident_summary": (
                "P2 — BGP route withdrawal isolating payment-service from 61% of users. "
                "Requires: restore BGP routes, roll back router config, verify checkout recovery."
            ),
            "alert": {
                "id": "ALT-RP-002",
                "title": "HIGH: checkout 61% failure — BGP network partition AZ-2/AZ-3",
                "severity_fired": "P2",
                "affected_services": ["network-infra", "order-service", "payment-service"],
            },
            "known_services": {
                "network-infra", "order-service", "payment-service",
                "fraud-detection-service", "postgres-db",
            },
            "tool_responses": {
                "query_logs": {
                    "network-infra": (
                        "CRITICAL: BGP route withdrawal — AZ-2/AZ-3 lost route to AZ-1 10.0.1.0/24\n"
                        "Router config change 18min ago: BGP advertisement policy update"
                    ),
                    "order-service": "ERROR: connection timeout payment-service — no route to host",
                    "payment-service": "INFO: AZ-1 traffic normal | WARN: cross-AZ health checks failing",
                },
                "check_metrics": {
                    "network-infra": "BGP AZ-2: DOWN | BGP AZ-3: DOWN | AZ-1: UP",
                    "order-service": "AZ-2 failure: 99% | AZ-1 failure: 0.2%",
                    "payment-service": "AZ-1 normal | Cross-AZ inbound: 0",
                },
                "check_dependencies": {
                    "order-service": "Depends on: payment-service [PARTITIONED]",
                    "payment-service": "Depends on: postgres-db [OK]",
                    "network-infra": "BGP peers: AZ-2 [DOWN], AZ-3 [DOWN]",
                },
                "check_recent_deploys": {
                    "network-infra": "Config change 18min ago — BGP policy update withdrew AZ-1 routes",
                    "payment-service": "No recent deploys",
                },
                "check_service_status": {
                    "network-infra": "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN",
                    "payment-service": "HEALTHY (AZ-1 only) | Cross-AZ: UNREACHABLE",
                    "order-service": "DEGRADED",
                },
            },
            "remediation_data": {
                "rollback_deploy": {
                    "network-infra": "Router config rolled back — BGP advertisement policy restored",
                },
                "execute_runbook_step": {
                    "restore_bgp_routes": "BGP routes restored — AZ-2/AZ-3 can reach AZ-1",
                    "verify_checkout_recovery": "Checkout failure rate: 0.3% — incident resolved",
                },
            },
            "correct_severity": "P2",
            "correct_root_cause": {
                "service": "network-infra",
                "failure_mode": "BGP route withdrawal network partition",
            },
            "correct_remediation_sequence": [
                "execute_runbook_step:restore_bgp_routes",
                "rollback_deploy:network-infra",
                "execute_runbook_step:verify_checkout_recovery",
            ],
            "wrong_actions": {
                "restart_service:payment-service": "payment-service is healthy — network is the issue",
                "scale_service:payment-service": "Scaling won't fix a routing problem",
                "restart_service:order-service": "order-service is a victim",
                "clear_cache": "Cache is unrelated to network routing",
            },
            "resolution_keywords": [
                "bgp", "network", "route", "rollback", "partition", "restored",
                "az-1", "az-2", "az-3", "checkout",
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_task(task_id: str) -> dict:
    if task_id not in ALL_TASKS:
        raise ValueError(f"Unknown task_id '{task_id}'. Valid: {list(ALL_TASKS)}")
    return ALL_TASKS[task_id]


def get_scenario(task_id: str, index: int) -> dict:
    if task_id not in SCENARIOS:
        raise ValueError(f"No scenarios for task_id '{task_id}'.")
    scenarios = SCENARIOS[task_id]
    if index < 0 or index >= len(scenarios):
        raise ValueError(
            f"Scenario index {index} out of range for task '{task_id}' "
            f"(has {len(scenarios)} scenarios: 0–{len(scenarios)-1})."
        )
    return scenarios[index]


def list_tasks() -> list:
    return list(ALL_TASKS.values())
