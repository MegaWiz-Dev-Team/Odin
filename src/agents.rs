use std::env;
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use reqwest::Client;
use serde_json::{Value, json};

#[derive(Clone)]
pub struct AgentConfig {
    pub heimdall_url: String,
    pub heimdall_model: String,
    pub heimdall_api_key: Option<String>,
    pub tyr_url: String,
    pub tyr_user: String,
    pub tyr_pass: String,
    pub tyr_indexer_url: String,
    pub tyr_indexer_user: String,
    pub tyr_indexer_pass: String,
    pub vardr_url: String,
    pub huginn_url: String,
    pub muninn_url: String,
    pub forseti_url: String,
    pub mjolnir_url: String,
    pub loki_url: String,
    pub ratatoskr_url: String,
    pub laminar_url: String,
    pub github_token: Option<String>,
    pub github_api_url: String,
    pub discord_token: Option<String>,
    pub discord_channel_id: String,
    pub discord_webhook_url: Option<String>,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        Self {
            heimdall_url: env::var("HEIMDALL_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:8080".into()),
            heimdall_model: env::var("HEIMDALL_MODEL")
                .unwrap_or_else(|_| "claude-sonnet-4-6".into()),
            heimdall_api_key: env::var("HEIMDALL_API_KEY").ok(),
            tyr_url: env::var("TYR_URL")
                .unwrap_or_else(|_| "https://wazuh-manager.wazuh.svc.cluster.local:55000".into()),
            tyr_user: env::var("TYR_USER").unwrap_or_else(|_| "wazuh".into()),
            tyr_pass: env::var("TYR_PASS").unwrap_or_else(|_| "wazuh".into()),
            tyr_indexer_url: env::var("TYR_INDEXER_URL")
                .unwrap_or_else(|_| "https://wazuh-indexer.wazuh.svc.cluster.local:9200".into()),
            tyr_indexer_user: env::var("TYR_INDEXER_USER").unwrap_or_else(|_| "admin".into()),
            tyr_indexer_pass: env::var("TYR_INDEXER_PASS").unwrap_or_else(|_| "admin".into()),
            vardr_url: env::var("VARDR_URL")
                .unwrap_or_else(|_| "http://vardr.asgard.svc.cluster.local:9090".into()),
            huginn_url: env::var("HUGINN_URL")
                .unwrap_or_else(|_| "http://huginn.asgard.svc.cluster.local:8400".into()),
            muninn_url: env::var("MUNINN_URL")
                .unwrap_or_else(|_| "http://muninn.asgard.svc.cluster.local:8500".into()),
            forseti_url: env::var("FORSETI_URL")
                .unwrap_or_else(|_| "http://forseti.asgard.svc.cluster.local:5555".into()),
            mjolnir_url: env::var("MJOLNIR_URL")
                .unwrap_or_else(|_| "http://mjolnir.asgard.svc.cluster.local:8700".into()),
            loki_url: env::var("LOKI_URL")
                .unwrap_or_else(|_| "http://loki-api.asgard.svc.cluster.local:8000".into()),
            ratatoskr_url: env::var("RATATOSKR_URL")
                .unwrap_or_else(|_| "http://ratatoskr.asgard.svc.cluster.local:9200".into()),
            laminar_url: env::var("LAMINAR_URL")
                .unwrap_or_else(|_| "http://laminar-app-server.asgard.svc.cluster.local:8000".into()),
            github_token: env::var("GITHUB_TOKEN").ok().filter(|s| !s.is_empty()),
            github_api_url: env::var("GITHUB_API_URL")
                .unwrap_or_else(|_| "https://api.github.com".into()),
            discord_token: env::var("DISCORD_TOKEN").ok(),
            discord_channel_id: env::var("DISCORD_CHANNEL_ID").unwrap_or_default(),
            discord_webhook_url: env::var("DISCORD_WEBHOOK_URL").ok(),
        }
    }
}

pub fn http_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("reqwest client")
}

pub fn http_client_streaming() -> Client {
    // Long-lived client for SSE streams (LLM chat). reqwest's `timeout` covers
    // the *whole* request including stream duration — 15s cuts summaries mid-flight.
    Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .expect("reqwest streaming client")
}

pub async fn dispatch_tool(cfg: &AgentConfig, name: &str, args: &Value) -> Result<Value> {
    let client = http_client();
    match name {
        "tyr_manager_info" => tyr_get(&client, cfg, "/manager/info").await,
        "tyr_list_agents" => tyr_get(&client, cfg, "/agents?limit=50&pretty=true").await,
        "tyr_list_rules" => tyr_get(&client, cfg, "/rules?limit=20").await,
        "tyr_search_alerts" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("*");
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(20).min(100);
            tyr_search_alerts(&client, cfg, q, size).await
        }

        "vardr_health" => json_get(&client, &format!("{}/health", cfg.vardr_url)).await,
        "vardr_list_services" => json_get(&client, &format!("{}/api/services", cfg.vardr_url)).await,
        "vardr_list_alerts" => json_get(&client, &format!("{}/api/alerts", cfg.vardr_url)).await,
        "vardr_metrics" => json_get(&client, &format!("{}/api/metrics", cfg.vardr_url)).await,

        "huginn_health" => json_get(&client, &format!("{}/health", cfg.huginn_url)).await,
        "huginn_list_scans" => json_get(&client, &format!("{}/api/scans", cfg.huginn_url)).await,
        "huginn_get_findings" => {
            let id = arg_str(args, "scan_id")?;
            json_get(&client, &format!("{}/api/scans/{}/findings", cfg.huginn_url, id)).await
        }
        "huginn_stats" => json_get(&client, &format!("{}/api/stats", cfg.huginn_url)).await,
        "huginn_start_scan" => {
            let target = arg_str(args, "target")?;
            let scan_type = args.get("scan_type").and_then(|v| v.as_str()).unwrap_or("zap_baseline");
            let project = args.get("project").and_then(|v| v.as_str());
            let body = json!({
                "target": target,
                "scan_type": scan_type,
                "project": project
            });
            json_post(&client, &format!("{}/api/scan", cfg.huginn_url), &body, None).await
        }
        "huginn_scan_status" => {
            let id = arg_str(args, "scan_id")?;
            json_get(&client, &format!("{}/api/scans/{}", cfg.huginn_url, id)).await
        }
        "huginn_batch_scan" => {
            let profile = args.get("profile").and_then(|v| v.as_str()).unwrap_or("priority1");
            let sprint = args.get("sprint").and_then(|v| v.as_str());
            let body = json!({
                "profile": profile,
                "sprint": sprint
            });
            json_post(&client, &format!("{}/api/scan/batch", cfg.huginn_url), &body, None).await
        }

        "muninn_health" => json_get(&client, &format!("{}/health", cfg.muninn_url)).await,
        "muninn_list_issues" => json_get(&client, &format!("{}/api/issues", cfg.muninn_url)).await,
        "muninn_get_issue" => {
            let id = arg_str(args, "issue_id")?;
            json_get(&client, &format!("{}/api/issues/{}", cfg.muninn_url, id)).await
        }
        "muninn_stats" => json_get(&client, &format!("{}/api/stats", cfg.muninn_url)).await,

        "forseti_list_runs" => json_get(&client, &format!("{}/api/runs?limit=20", cfg.forseti_url)).await,
        "forseti_get_run" => {
            let id = arg_str(args, "run_id")?;
            json_get(&client, &format!("{}/api/runs/{}", cfg.forseti_url, id)).await
        }
        "forseti_list_suites" => json_get(&client, &format!("{}/api/suites", cfg.forseti_url)).await,
        "forseti_trend" => json_get(&client, &format!("{}/api/trend?limit=20", cfg.forseti_url)).await,

        "mjolnir_healthz" => json_get(&client, &format!("{}/healthz", cfg.mjolnir_url)).await,
        "mjolnir_list_runs" => json_get(&client, &format!("{}/api/runs", cfg.mjolnir_url)).await,
        "mjolnir_run_status" => {
            let id = arg_str(args, "run_id")?;
            json_get(&client, &format!("{}/api/load/status/{}", cfg.mjolnir_url, id)).await
        }
        "mjolnir_run_results" => {
            let id = arg_str(args, "run_id")?;
            json_get(&client, &format!("{}/api/load/results/{}", cfg.mjolnir_url, id)).await
        }

        // Loki — authorized pen-test system (read-only here; no attack trigger)
        "loki_list_results" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(200);
            json_get(&client, &format!("{}/api/v1/loki/results?limit={}", cfg.loki_url, limit)).await
        }
        "loki_stats" => json_get(&client, &format!("{}/api/v1/loki/results/stats", cfg.loki_url)).await,

        // Ratatoskr — shared headless browser service (health only; scrape/screenshot
        // are write-actions reserved for a future Thor-gated tier)
        "ratatoskr_health" => json_get(&client, &format!("{}/healthz", cfg.ratatoskr_url)).await,

        // propose_github_issue — READ-ONLY: resolves repo, runs dedup check, returns a
        // proposal for the human to confirm. Does NOT create the issue (HITL).
        // Actual creation happens via the POST /api/issues/create endpoint after a click.
        "propose_github_issue" => {
            let service = arg_str(args, "service").unwrap_or_default();
            let title = arg_str(args, "title")?;
            let repo = service_to_repo(&service);
            let fp = issue_fingerprint(&repo, &title);
            // dedup lookup in the odin-issue-dedup index (Odin has indexer creds)
            let existing = dedup_lookup(&client, cfg, &fp).await;
            Ok(json!({
                "action": "propose_github_issue",
                "repo": repo,
                "title": title,
                "body": args.get("body").and_then(|v| v.as_str()).unwrap_or(""),
                "fingerprint": fp,
                "duplicate_of": existing,   // url if already filed, else null
                "needs_confirmation": true,
                "note": "Proposal only — confirm in the UI to create. Will be skipped if duplicate_of is set."
            }))
        }

        _ => Err(anyhow!("unknown tool: {}", name)),
    }
}

async fn tyr_get(client: &Client, cfg: &AgentConfig, path: &str) -> Result<Value> {
    // Step 1 — basic auth → JWT
    let creds = format!("{}:{}", cfg.tyr_user, cfg.tyr_pass);
    let basic = format!("Basic {}", B64.encode(creds.as_bytes()));
    let auth_url = format!("{}/security/user/authenticate", cfg.tyr_url);
    let auth_res = client
        .get(&auth_url)
        .header("Authorization", &basic)
        .send()
        .await
        .map_err(|e| anyhow!("tyr auth request failed: {}", e))?;
    if !auth_res.status().is_success() {
        let s = auth_res.status();
        let b = auth_res.text().await.unwrap_or_default();
        return Ok(json!({ "error": format!("tyr auth {}: {}", s, b) }));
    }
    let auth_json: Value = auth_res.json().await
        .map_err(|e| anyhow!("tyr auth json parse: {}", e))?;
    let jwt = auth_json
        .pointer("/data/token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no JWT in tyr auth response"))?;

    // Step 2 — call actual endpoint with JWT bearer
    let url = format!("{}{}", cfg.tyr_url, path);
    let res = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .send()
        .await
        .map_err(|e| anyhow!("tyr request failed: {}", e))?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if !status.is_success() {
        return Ok(json!({ "error": format!("tyr {}: {}", status, body) }));
    }
    serde_json::from_str(&body).map_err(|e| anyhow!("tyr json parse: {}", e))
}

async fn tyr_search_alerts(client: &Client, cfg: &AgentConfig, query: &str, size: u64) -> Result<Value> {
    let creds = format!("{}:{}", cfg.tyr_indexer_user, cfg.tyr_indexer_pass);
    let basic = format!("Basic {}", B64.encode(creds.as_bytes()));
    let url = format!("{}/wazuh-alerts-*/_search", cfg.tyr_indexer_url);
    let body = json!({
        "size": size,
        "sort": [{ "@timestamp": { "order": "desc" } }],
        "query": {
            "query_string": {
                "query": query,
                "default_field": "*"
            }
        },
        "_source": ["@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups", "agent.name", "data"]
    });
    let res = client
        .post(&url)
        .header("Authorization", basic)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("indexer request failed: {}", e))?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if !status.is_success() {
        return Ok(json!({ "error": format!("indexer {}: {}", status, text) }));
    }
    let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    // Trim to just hits.hits[]._source for the LLM (saves tokens)
    let hits = parsed
        .pointer("/hits/hits")
        .and_then(|h| h.as_array())
        .map(|arr| arr.iter().filter_map(|h| h.get("_source").cloned()).collect::<Vec<_>>())
        .unwrap_or_default();
    let total = parsed.pointer("/hits/total/value").cloned().unwrap_or(json!(hits.len()));
    Ok(json!({ "total": total, "alerts": hits }))
}

async fn json_get(client: &Client, url: &str) -> Result<Value> {
    let res = client.get(url).send().await;
    match res {
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return Ok(json!({ "error": format!("{}: {}", status, body), "url": url }));
            }
            Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body })))
        }
        Err(e) => Ok(json!({ "error": format!("unreachable: {}", e), "url": url })),
    }
}

fn arg_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing arg: {}", key))
}

/// Map a scanned/alerting service name → real GitHub `owner/repo`.
/// Mirrors Huginn's mapping so Odin and Huginn file to the same place.
pub fn service_to_repo(service: &str) -> String {
    const ORG: &str = "MegaWiz-Dev-Team";
    let repo = match service.to_lowercase().as_str() {
        "mimir-api" | "mimir-dashboard" | "mimir" => "Mimir",
        "syn-api" | "syn" => "Syn",
        "eir-gateway" | "eir" => "Eir",
        "bifrost" => "Bifrost",
        "heimdall" | "heimdall-host" => "Heimdall",
        "huginn" => "Huginn",
        "muninn" => "Muninn",
        "odin" => "Odin",
        "loki" | "loki-api" => "Loki",
        "tyr" | "wazuh-manager" | "wazuh-indexer" => "Tyr",
        "vardr" => "Vardr",
        "forseti" => "Forseti",
        "mjolnir" => "Mjolnir",
        "ratatoskr" => "Ratatoskr",
        "yggdrasil" => "Yggdrasil",
        "hermodr" => "Hermodr",
        _ => "Asgard",
    };
    format!("{}/{}", ORG, repo)
}

/// Stable fingerprint for an issue = deterministic hash of repo+title.
/// Used to dedup so the same finding/alert doesn't open duplicate issues.
pub fn issue_fingerprint(repo: &str, title: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    repo.hash(&mut h);
    title.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Look up an existing issue by fingerprint in the `odin-issue-dedup` index.
/// Returns the issue URL if already filed (→ caller skips creation), else None.
pub async fn dedup_lookup(client: &Client, cfg: &AgentConfig, fingerprint: &str) -> Option<String> {
    let url = format!("{}/odin-issue-dedup/_doc/{}", cfg.tyr_indexer_url, fingerprint);
    let r = client
        .get(&url)
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None; // 404 = not seen before
    }
    let v: Value = r.json().await.ok()?;
    v.pointer("/_source/issue_url").and_then(|u| u.as_str()).map(|s| s.to_string())
}

/// Record a created issue's fingerprint → url in the dedup index.
pub async fn dedup_record(client: &Client, cfg: &AgentConfig, fingerprint: &str, repo: &str, title: &str, issue_url: &str) {
    let url = format!("{}/odin-issue-dedup/_doc/{}", cfg.tyr_indexer_url, fingerprint);
    let body = json!({ "repo": repo, "title": title, "issue_url": issue_url });
    let _ = client
        .put(&url)
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .json(&body)
        .send()
        .await;
}

/// POST JSON to a URL, optionally setting X-Tenant-Id header.
async fn json_post(client: &Client, url: &str, body: &Value, tenant_id: Option<&str>) -> Result<Value> {
    let mut req = client.post(url).json(body);
    if let Some(tid) = tenant_id {
        req = req.header("X-Tenant-Id", tid);
    }
    let res = req.send().await;
    match res {
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return Ok(json!({ "error": format!("{}: {}", status, text), "url": url }));
            }
            Ok(serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text })))
        }
        Err(e) => Ok(json!({ "error": format!("unreachable: {}", e), "url": url })),
    }
}


pub fn tool_definitions() -> Value {
    json!([
        // Týr — Wazuh SIEM
        tool("tyr_manager_info", "Týr (Wazuh SIEM): get manager cluster info and version", json!({})),
        tool("tyr_list_agents", "Týr: list registered Wazuh agents and their connection status", json!({})),
        tool("tyr_list_rules", "Týr: list detection rules (first 20)", json!({})),
        tool("tyr_search_alerts", "Týr: search Wazuh alerts in the indexer (OpenSearch). Use Lucene query syntax — e.g. '*' for recent, 'rule.level:>=10' for critical, 'rule.description:LLM01' for prompt-injection alerts, 'rule.groups:asgard' for Asgard-tagged alerts. Returns alerts sorted newest first.", json!({
            "query": { "type": "string", "description": "Lucene query, default '*' (last N alerts)" },
            "size": { "type": "integer", "description": "max alerts to return, default 20, max 100" }
        })),

        // Várðr — Monitoring
        tool("vardr_health", "Várðr (Monitoring): service health", json!({})),
        tool("vardr_list_services", "Várðr: list all monitored services and container states", json!({})),
        tool("vardr_list_alerts", "Várðr: active monitoring alerts", json!({})),
        tool("vardr_metrics", "Várðr: current CPU/memory/disk usage per service", json!({})),

        // Huginn — Security Scanner (offensive)
        tool("huginn_health", "Huginn (Security Scanner): service health", json!({})),
        tool("huginn_list_scans", "Huginn: list recent security scans", json!({})),
        tool("huginn_get_findings", "Huginn: detailed vulnerability findings for a scan", json!({
            "scan_id": { "type": "string", "description": "scan id from list_scans" }
        })),
        tool("huginn_stats", "Huginn: aggregate scanner stats", json!({})),
        tool("huginn_start_scan", "Huginn: start a single VA scan (zap_baseline/zap_openapi/llm) on a target service", json!({
            "target": { "type": "string", "description": "service URL to scan (e.g. http://mimir-api.asgard.svc:8080)" },
            "scan_type": { "type": "string", "description": "scan type: zap_baseline (OWASP Top 10), zap_openapi (API spec), zap_full (aggressive), llm (LLM security probe)" },
            "project": { "type": "string", "description": "optional project name for grouping scans" }
        })),
        tool("huginn_scan_status", "Huginn: get status and findings count for a running or completed scan", json!({
            "scan_id": { "type": "string", "description": "scan id returned from start_scan" }
        })),
        tool("huginn_batch_scan", "Huginn: trigger batch VA scan across multiple services (nightly equivalent). Returns all scan IDs", json!({
            "profile": { "type": "string", "description": "profile: all (17 services), priority1 (4 high-risk), priority2 (5 medium-risk), priority3 (6 low-risk)" },
            "sprint": { "type": "string", "description": "optional sprint label for grouping findings" }
        })),

        // Muninn — Issue Watcher / Auto-Fixer
        tool("muninn_health", "Muninn (Issue Watcher): service health", json!({})),
        tool("muninn_list_issues", "Muninn: list watched issues and their status", json!({})),
        tool("muninn_get_issue", "Muninn: detail for a single issue including remediation suggestions", json!({
            "issue_id": { "type": "string", "description": "issue id" }
        })),
        tool("muninn_stats", "Muninn: aggregate issue stats", json!({})),

        // Forseti — E2E testing
        tool("forseti_list_runs", "Forseti (E2E Testing): list recent test runs (limit 20)", json!({})),
        tool("forseti_get_run", "Forseti: detailed results for a test run", json!({
            "run_id": { "type": "string", "description": "run id" }
        })),
        tool("forseti_list_suites", "Forseti: list registered test suites", json!({})),
        tool("forseti_trend", "Forseti: pass/fail trend over recent runs", json!({})),

        // Mjölnir — HTTP load testing
        tool("mjolnir_healthz", "Mjölnir (Load Testing): service health", json!({})),
        tool("mjolnir_list_runs", "Mjölnir: list recent load-test runs and their status", json!({})),
        tool("mjolnir_run_status", "Mjölnir: get status of a specific load-test run", json!({
            "run_id": { "type": "string", "description": "load test run id" }
        })),
        tool("mjolnir_run_results", "Mjölnir: get full results (latency, throughput, errors) for a load-test run", json!({
            "run_id": { "type": "string", "description": "load test run id" }
        })),

        // Loki — Authorized Penetration Testing System (red team)
        tool("loki_list_results", "Loki (Authorized Pen-Test / Red Team): list recent offensive security test results — API injection, prompt injection, data exfiltration, SIEM evasion attempts run against Asgard services. Pairs with Tyr: Loki attacks, Tyr detects.", json!({
            "limit": { "type": "integer", "description": "max results, default 50, max 200" }
        })),
        tool("loki_stats", "Loki: aggregate pen-test stats — counts by severity and by test_type, plus recent tests", json!({})),

        // Ratatoskr — shared headless browser service
        tool("ratatoskr_health", "Ratatoskr (shared headless browser): service health + session pool status", json!({})),

        // propose_github_issue — staged write (T2). Returns a proposal for the human to
        // confirm in the UI; does NOT create the issue itself. Use after triaging an
        // alert/finding when the user asks to file/track it.
        tool("propose_github_issue", "Propose a GitHub issue for a finding/alert (does NOT create it — returns a proposal the human confirms with a button). Auto-resolves the target repo from the service name and checks for duplicates.", json!({
            "service": { "type": "string", "description": "service the issue is about, e.g. 'eir-gateway', 'mimir-api', 'tyr' — used to pick the repo" },
            "title": { "type": "string", "description": "concise issue title" },
            "body": { "type": "string", "description": "issue body in markdown (summary, evidence, remediation)" }
        })),
    ])
}

fn tool(name: &str, desc: &str, props: Value) -> Value {
    let required: Vec<String> = props
        .as_object()
        .map(|o| o.keys().filter(|k| *k != "session_id").cloned().collect())
        .unwrap_or_default();
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required,
            }
        }
    })
}
