# Asgard System Inspection Runbook / คู่มือตรวจระบบ Asgard

Operational checks for an Asgard on-prem box (1 Mac mini / customer). Each row =
what to check, the exact command, and pass/fail criteria. Six domains: Availability
(Várðr), Vulnerability (Huginn), Adversarial (Loki), Detection (Týr), Remediation
(Muninn), Governance (Thor + audit).

> ⚠️ **Resource rule (Mac mini):** never run heavy jobs concurrently (Huginn batch /
> Loki campaign / Mjölnir load / docker build) — concurrent heavy load has caused
> kernel panics. Schedule them serial + off-peak; `sudo purge` + check RAM headroom
> before a heavy run.

Conventions: `NS=asgard`. Mimir DB on `mariadb.asgard-infra.svc`. Heimdall gateway
on host `:8080`. Cron entries that are automated are noted; the rest are manual until
the CronJobs in `k8s/02-ops-cronjobs.yaml` are applied.

---

## Continuous (automated ~60s)

| Check | Command | Pass |
|---|---|---|
| All services online | Odin dashboard → Services tab, or `GET /api/health-proxy` | every tile Online (Laminar may be expected-off) |
| SIEM alerts | Odin chat → Týr, or Wazuh indexer `/_search` | no unacked Critical |
| Heimdall gateway | `curl -s localhost:8080/JSON/...`/`/health` | 200, no 502 |
| RAM/disk headroom | `kubectl top nodes`; host `vm_stat` | RAM headroom > ~4 GB free |

## Daily

| Check | Command | Pass / Fail |
|---|---|---|
| Alert triage | review Týr alerts since yesterday | all High/Critical triaged |
| Issue backlog | `GET muninn:8500/api/stats` (or Odin dashboard) | `total_issues` stable, `failed`=0 |
| VA nightly result | `GET huginn:8400/api/scans` (cron `huginn-nightly-va-scan` 03:00) | scan `completed`, new High/Critical → tracked as issue |
| Backup verify | host: `scripts/backup-full-k8s.sh` output + `ls -lh <T7>/…/MANIFEST` | latest backup has MANIFEST + valid gzip (`gzip -t`) |
| Heimdall model/latency | `curl localhost:8080/v1/models` | gemma-4-26b loaded; p50 latency normal |

## Weekly

| Check | Command | Pass / Fail |
|---|---|---|
| Full VA (all services) | cron `huginn-nightly-va-scan` profile=all | findings filed as issues (scan→issue loop) |
| **Red-team + purple-team** | cron `loki-weekly-redteam` → then check Týr detected it | Loki ran; Týr raised matching detections (not silent) |
| **Dependency / CVE sweep** | cron `cve-sweep-weekly` (`trivy k8s`) | no new HIGH/CRITICAL in images/workloads |
| Thor policy audit | Odin → Policy/Audit tab (`GET /api/audit`) | every merge/active-response decision logged; no bypass |
| E2E + load | Forseti runs; `GET mjolnir/api/...` | pass-rate steady; latency/error not regressed |
| Muninn fix backlog | `GET muninn:8500/api/issues` | Pending not growing unbounded |

## Monthly

| Check | Command | Pass / Fail |
|---|---|---|
| **Cert / JWT expiry** | cron `cert-expiry-weekly`, or `openssl s_client -connect <auth>:443 \| openssl x509 -noout -enddate` | nothing expiring < 30 days |
| KB freshness | `GET mimir:8080/api/v1/knowledge/shared` | embeddings present; vintage acceptable |
| Capacity / trend | `kubectl top` history; Várðr metrics | within budget |
| **Restore test** | restore latest backup into a scratch ns, verify it boots | backup is actually recoverable |
| Access review | review tokens/SA/RBAC | least-privilege holds |

## Quarterly

| Check | Pass |
|---|---|
| Compliance (ISO 29110) | `Asgard/docs/iso_29110/` current; audit trail complete |
| Threat-model refresh | reviewed for new AI/infra threats |
| Rego policy review (Thor) | `merge/create/active_response` policies still correct |
| DR drill | full restore + failover rehearsed |

---

## Tool quick-reference (exact endpoints)

```sh
# VA scan (Huginn) — single + batch
curl -X POST http://huginn.asgard.svc:8400/api/scan       -d '{"target":"http://mimir-api.asgard.svc:8080","scan_type":"zapbaseline"}'
curl -X POST http://huginn.asgard.svc:8400/api/scan/batch -d '{"profile":"all","sprint":"weekly"}'
curl -s http://huginn.asgard.svc:8400/api/scans            # results

# Red-team (Loki) — needs X-Loki-Test header
curl -X POST http://loki-api.asgard.svc:8000/api/v1/loki/scan \
  -H 'X-Loki-Test: true' -d '{"targets":["http://eir-gateway.asgard.svc:3000"],"environment":"production"}'

# Issues (Muninn) — what the dashboard "Total Issues" counts
curl -s http://muninn.asgard.svc:8500/api/issues
curl -s http://muninn.asgard.svc:8500/api/stats

# CVE sweep (trivy against the cluster)
trivy k8s --namespace asgard --severity HIGH,CRITICAL --report summary

# Cert expiry (auth endpoint)
echo | openssl s_client -connect <auth-host>:443 2>/dev/null | openssl x509 -noout -enddate

# Backup + verify (HOST side — T7 is a host volume, not in-cluster)
./scripts/backup-full-k8s.sh && gzip -t "<T7>/asgard-backup-*/MANIFEST"*.gz
```

### scan→issue→fix loop (how findings reach the dashboard)
Huginn finds → `on_scan_complete` files a GitHub issue (≥ `NOTIFY_MIN_SEVERITY`, label
`vulnerability`) on the scanned service's repo → **Muninn must watch that repo**
(`WATCHED_REPOS`) → tracks it → Odin dashboard "Total Issues" → Muninn auto-fixes
(draft PR). Gotchas: `NOTIFY_MIN_SEVERITY` must be ≤ finding severity (default `high`
skips Medium); `GITHUB_TOKEN`/`GITHUB_API_URL` must be set (huginn-secrets); issue
labels must intersect Muninn `WATCH_LABELS` (security/vulnerability/huginn-finding/auto-fix).
