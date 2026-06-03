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
    // Mimir — RAG knowledge base (Odin's AI-security KB, e.g. NCSA AI Security Guidelines)
    pub mimir_url: String,
    pub mimir_tenant: String,
    pub mimir_kb_source_ids: Vec<i64>,
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
                // Default to Gemini 3.1 flash-lite via Heimdall's gemini/ routing.
                // claude-sonnet-4-6 routing through the gateway is currently broken
                // (HTTP 000 / times out), so it is not a safe fallback.
                .unwrap_or_else(|_| "gemini/gemini-3.1-flash-lite".into()),
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
            mimir_url: env::var("MIMIR_URL")
                .unwrap_or_else(|_| "http://mimir-api.asgard.svc:8080".into()),
            mimir_tenant: env::var("MIMIR_TENANT").unwrap_or_else(|_| "asgard_platform".into()),
            // Optional comma-separated data-source IDs to scope KB search to (e.g. "3" =
            // NCSA AI Security Guidelines). Empty = search the whole tenant KB.
            mimir_kb_source_ids: env::var("MIMIR_KB_SOURCE_IDS")
                .unwrap_or_default()
                .split(',')
                .filter_map(|s| s.trim().parse::<i64>().ok())
                .collect(),
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

        // Mimir — query the AI-security knowledge base (RAG)
        "knowledge_search" => {
            let query = arg_str(args, "query")?;
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(5).min(10);
            knowledge_search(&client, cfg, &query, limit).await
        }

        // Phase 5 — GitHub PR review/merge
        "gh_pr_list" => {
            let repo = resolve_repo(args);
            let state = args.get("state").and_then(|v| v.as_str()).unwrap_or("open");
            Ok(gh_pr_list(&client, cfg, &repo, state).await)
        }
        "gh_pr_get" => {
            let repo = resolve_repo(args);
            let number = args
                .get("number")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing arg: number"))?;
            Ok(gh_pr_get(&client, cfg, &repo, number).await)
        }
        // propose_pr_merge — READ-ONLY proposal (T3 gated). Returns PR review info +
        // needs_confirmation; the actual merge happens via POST /api/pulls/merge after a click.
        "propose_pr_merge" => {
            let repo = resolve_repo(args);
            let number = args
                .get("number")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing arg: number"))?;
            let pr = gh_pr_get(&client, cfg, &repo, number).await;
            Ok(json!({
                "action": "propose_pr_merge",
                "repo": repo,
                "number": number,
                "title": pr.get("title"),
                "draft": pr.get("draft"),
                "mergeable": pr.get("mergeable"),
                "mergeable_state": pr.get("mergeable_state"),
                "base": pr.get("base"),
                "url": pr.get("url"),
                "needs_confirmation": true,
                "tier": "T3",
                "note": "Proposal only — confirm in the UI to merge (T3 prod write). Draft PRs must be marked ready-for-review first."
            }))
        }

        // propose_active_response — READ-ONLY proposal (T3 gated). The real send
        // happens via POST /api/active-response after a click (Thor-gated).
        "propose_active_response" => {
            let command = arg_str(args, "command")?;
            let agents: Vec<String> = args
                .get("agents")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            Ok(json!({
                "action": "propose_active_response",
                "command": command,
                "agents": agents,
                "needs_confirmation": true,
                "tier": "T3",
                "note": "Proposal only — confirm in the UI to send the Active Response (T3). Gated by Thor policy; requires AR configured on the Wazuh side to actually execute."
            }))
        }

        _ => Err(anyhow!("unknown tool: {}", name)),
    }
}

/// Query Mimir's RAG knowledge base for the configured tenant, optionally scoped
/// to specific data sources (Odin's AI-security KB). Uses Mimir's dense vector
/// search endpoint (`/api/v1/vector/search`) — the hybrid `/api/search` path
/// currently collapses dense results via a broken BM25 fusion, so we hit the
/// vector endpoint directly for reliable semantic recall. Returns a trimmed list
/// of {score, content} for the LLM to ground its answer on.
pub async fn knowledge_search(client: &Client, cfg: &AgentConfig, query: &str, limit: u64) -> Result<Value> {
    let mut body = json!({
        "query": query,
        "limit": limit,
    });
    if !cfg.mimir_kb_source_ids.is_empty() {
        body["source_ids"] = json!(cfg.mimir_kb_source_ids);
    }
    let url = format!("{}/api/v1/vector/search", cfg.mimir_url);
    let res = client
        .post(&url)
        .header("X-Tenant-Id", &cfg.mimir_tenant)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;
    match res {
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return Ok(json!({ "error": format!("mimir {}: {}", status, text), "url": url }));
            }
            let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
            // Response shape: { result: { points: [ { score, payload: { content } } ] } }
            let results = parsed
                .pointer("/result/points")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|h| json!({
                            "score": h.get("score").cloned().unwrap_or(json!(null)),
                            "content": h.pointer("/payload/content").and_then(|c| c.as_str()).unwrap_or(""),
                        }))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(json!({
                "query": query,
                "count": results.len(),
                "results": results,
                "source": "NCSA AI Security Guidelines (asgard_platform KB)"
            }))
        }
        Err(e) => Ok(json!({ "error": format!("mimir unreachable: {}", e), "url": url })),
    }
}

/// Wazuh manager API auth: basic creds → short-lived JWT.
async fn tyr_jwt(client: &Client, cfg: &AgentConfig) -> Result<String> {
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
        return Err(anyhow!("tyr auth {}: {}", s, b));
    }
    let auth_json: Value = auth_res
        .json()
        .await
        .map_err(|e| anyhow!("tyr auth json parse: {}", e))?;
    auth_json
        .pointer("/data/token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no JWT in tyr auth response"))
}

async fn tyr_get(client: &Client, cfg: &AgentConfig, path: &str) -> Result<Value> {
    let jwt = match tyr_jwt(client, cfg).await {
        Ok(j) => j,
        Err(e) => return Ok(json!({ "error": e.to_string() })),
    };
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

/// Send a Wazuh Active Response command to agents (T3 enforcement). Called by
/// POST /api/active-response after human confirm + Thor gate. NOTE: actual
/// execution requires the AR command to be configured on the Wazuh side
/// (ossec.conf <active-response> + the script on agents).
pub async fn active_response_core(
    client: &Client,
    cfg: &AgentConfig,
    command: &str,
    agents: &[String],
    arguments: &[String],
) -> Value {
    let jwt = match tyr_jwt(client, cfg).await {
        Ok(j) => j,
        Err(e) => return json!({ "status": "error", "error": e.to_string() }),
    };
    let agents_list = if agents.is_empty() { "*".to_string() } else { agents.join(",") };
    let url = format!("{}/active-response?agents_list={}", cfg.tyr_url, agents_list);
    let body = json!({ "command": command, "arguments": arguments, "alert": {} });
    let res = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", jwt))
        .json(&body)
        .send()
        .await;
    match res {
        Ok(r) => {
            let ok = r.status().is_success();
            let v: Value = r.json().await.unwrap_or_default();
            if ok {
                json!({ "status": "sent", "command": command, "agents": agents, "result": v.get("data") })
            } else {
                json!({
                    "status": "error", "command": command,
                    "error": v.get("detail").or_else(|| v.get("title")).cloned().unwrap_or(json!("wazuh rejected"))
                })
            }
        }
        Err(e) => json!({ "status": "error", "error": format!("wazuh AR unreachable: {}", e) }),
    }
}

pub async fn tyr_search_alerts(client: &Client, cfg: &AgentConfig, query: &str, size: u64) -> Result<Value> {
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

/// Result of an issue-creation attempt. Shared shape for the HITL endpoint
/// and the autonomous Týr bridge.
pub struct IssueOutcome {
    pub status: &'static str, // "created" | "duplicate" | "error"
    pub issue_url: Option<String>,
    pub fingerprint: String,
    pub repo: String,
    pub error: Option<String>,
}

/// Core issue creation: dedup → create on GitHub → record fingerprint.
/// The single place an issue is actually filed; used by both `/api/issues/create`
/// (human-confirmed) and the Týr alert→issue bridge (autonomous). Requires
/// `cfg.github_token`; recurring identical (repo+title) findings are deduped.
pub async fn create_issue_core(
    client: &Client,
    cfg: &AgentConfig,
    repo: &str,
    title: &str,
    body: &str,
    labels: &[&str],
) -> IssueOutcome {
    let fp = issue_fingerprint(repo, title);

    if let Some(url) = dedup_lookup(client, cfg, &fp).await {
        return IssueOutcome {
            status: "duplicate",
            issue_url: Some(url),
            fingerprint: fp,
            repo: repo.to_string(),
            error: None,
        };
    }

    // Thor policy gate (create) — centralised here so BOTH the HITL endpoint and
    // the autonomous Týr bridge are governed (org allowlist, title/body sanity).
    let verdict = crate::policy::check_create(
        &crate::policy::CreatePolicy::from_env(), repo, title, body,
    );
    if !verdict.allow {
        return IssueOutcome {
            status: "denied",
            issue_url: None,
            fingerprint: fp,
            repo: repo.to_string(),
            error: Some(format!("Thor denied: {}", verdict.violations.join("; "))),
        };
    }

    let token = match &cfg.github_token {
        Some(t) => t.clone(),
        None => {
            return IssueOutcome {
                status: "error",
                issue_url: None,
                fingerprint: fp,
                repo: repo.to_string(),
                error: Some("GITHUB_TOKEN not configured on Odin".into()),
            }
        }
    };

    let url = format!("{}/repos/{}/issues", cfg.github_api_url, repo);
    let payload = json!({ "title": title, "body": body, "labels": labels });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "odin-orchestrator")
        .json(&payload)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let ok = r.status().is_success();
            let v: Value = r.json().await.unwrap_or_default();
            if ok {
                let issue_url = v
                    .get("html_url")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                dedup_record(client, cfg, &fp, repo, title, &issue_url).await;
                IssueOutcome {
                    status: "created",
                    issue_url: Some(issue_url),
                    fingerprint: fp,
                    repo: repo.to_string(),
                    error: None,
                }
            } else {
                IssueOutcome {
                    status: "error",
                    issue_url: None,
                    fingerprint: fp,
                    repo: repo.to_string(),
                    error: Some(format!(
                        "github rejected: {}",
                        v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
                    )),
                }
            }
        }
        Err(e) => IssueOutcome {
            status: "error",
            issue_url: None,
            fingerprint: fp,
            repo: repo.to_string(),
            error: Some(format!("github unreachable: {}", e)),
        },
    }
}

// ── Phase 5: GitHub PR review/merge ──────────────────────────────────────────

/// Resolve a target repo from tool args: prefer an explicit `repo` ("owner/repo"),
/// else map a `service` name via service_to_repo.
pub fn resolve_repo(args: &Value) -> String {
    if let Some(r) = args.get("repo").and_then(|v| v.as_str()).filter(|s| s.contains('/')) {
        return r.to_string();
    }
    service_to_repo(args.get("service").and_then(|v| v.as_str()).unwrap_or(""))
}

/// Authenticated GitHub GET → parsed JSON (or an {error} object — never panics).
async fn github_get_authed(client: &Client, cfg: &AgentConfig, url: &str) -> Value {
    let token = match &cfg.github_token {
        Some(t) => t.clone(),
        None => return json!({ "error": "GITHUB_TOKEN not configured on Odin", "url": url }),
    };
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "odin-orchestrator")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await;
    match resp {
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return json!({ "error": format!("github {}: {}", status, text), "url": url });
            }
            serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
        }
        Err(e) => json!({ "error": format!("github unreachable: {}", e), "url": url }),
    }
}

/// List PRs for a repo (trimmed for the LLM). T2 read.
pub async fn gh_pr_list(client: &Client, cfg: &AgentConfig, repo: &str, state: &str) -> Value {
    let url = format!(
        "{}/repos/{}/pulls?state={}&per_page=30&sort=updated&direction=desc",
        cfg.github_api_url, repo, state
    );
    let v = github_get_authed(client, cfg, &url).await;
    if v.get("error").is_some() {
        return v;
    }
    let prs = v
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    json!({
                        "number": p.get("number"),
                        "title": p.get("title"),
                        "draft": p.get("draft"),
                        "state": p.get("state"),
                        "user": p.pointer("/user/login"),
                        "head": p.pointer("/head/ref"),
                        "base": p.pointer("/base/ref"),
                        "url": p.get("html_url"),
                        "created_at": p.get("created_at"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({ "repo": repo, "count": prs.len(), "pulls": prs })
}

/// Get one PR: metadata + changed files with patches (for review). T2 read.
pub async fn gh_pr_get(client: &Client, cfg: &AgentConfig, repo: &str, number: u64) -> Value {
    let meta = github_get_authed(
        client, cfg,
        &format!("{}/repos/{}/pulls/{}", cfg.github_api_url, repo, number),
    ).await;
    if meta.get("error").is_some() {
        return meta;
    }
    let files = github_get_authed(
        client, cfg,
        &format!("{}/repos/{}/pulls/{}/files?per_page=50", cfg.github_api_url, repo, number),
    ).await;
    let files_trim = files
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|f| {
                    json!({
                        "filename": f.get("filename"),
                        "status": f.get("status"),
                        "additions": f.get("additions"),
                        "deletions": f.get("deletions"),
                        "patch": f.get("patch"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "repo": repo,
        "number": number,
        "title": meta.get("title"),
        "draft": meta.get("draft"),
        "state": meta.get("state"),
        "mergeable": meta.get("mergeable"),
        "mergeable_state": meta.get("mergeable_state"),
        "head": meta.pointer("/head/ref"),
        "base": meta.pointer("/base/ref"),
        "body": meta.get("body"),
        "url": meta.get("html_url"),
        "files": files_trim,
    })
}

/// Merge a PR (T3, prod write). Called by POST /api/pulls/merge after a human
/// confirms. `method` = merge | squash | rebase.
pub async fn merge_pr_core(
    client: &Client,
    cfg: &AgentConfig,
    repo: &str,
    number: u64,
    method: &str,
) -> Value {
    let token = match &cfg.github_token {
        Some(t) => t.clone(),
        None => return json!({ "status": "error", "error": "GITHUB_TOKEN not configured on Odin" }),
    };
    let url = format!("{}/repos/{}/pulls/{}/merge", cfg.github_api_url, repo, number);
    let payload = json!({ "merge_method": method });
    let resp = client
        .put(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "odin-orchestrator")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&payload)
        .send()
        .await;
    match resp {
        Ok(r) => {
            let ok = r.status().is_success();
            let v: Value = r.json().await.unwrap_or_default();
            if ok {
                json!({ "status": "merged", "repo": repo, "number": number, "sha": v.get("sha") })
            } else {
                json!({
                    "status": "error", "repo": repo, "number": number,
                    "error": v.get("message").and_then(|m| m.as_str()).unwrap_or("github rejected merge")
                })
            }
        }
        Err(e) => json!({ "status": "error", "error": format!("github unreachable: {}", e) }),
    }
}

/// Append an audit record to the `odin-audit` index (best-effort).
pub async fn audit_event(client: &Client, cfg: &AgentConfig, action: &str, details: Value) {
    let url = format!("{}/odin-audit/_doc", cfg.tyr_indexer_url);
    let mut body = json!({ "action": action, "actor": "odin", "ts": chrono::Utc::now().to_rfc3339() });
    if let (Some(obj), Some(extra)) = (body.as_object_mut(), details.as_object()) {
        for (k, v) in extra {
            obj.insert(k.clone(), v.clone());
        }
    }
    let _ = client
        .post(&url)
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

        // knowledge_search — Mimir RAG over the AI-security knowledge base
        tool("knowledge_search", "Search the AI Security knowledge base (NCSA 'AI Security Guidelines' / แนวปฏิบัติการใช้ปัญญาประดิษฐ์อย่างมั่นคงปลอดภัย, stored in Mimir). Use this to ground answers about AI/LLM threats (Prompt Injection, Data/Model Poisoning, Model Extraction, AI supply-chain attacks), secure AI lifecycle, risk assessment, and recommended controls/best-practices. Returns the most relevant passages (Thai). Query in Thai or English.", json!({
            "query": { "type": "string", "description": "natural-language question or keywords, e.g. 'การป้องกัน Prompt Injection' or 'AI supply chain attack controls'" },
            "limit": { "type": "integer", "description": "max passages to return, default 5, max 10" }
        })),

        // propose_github_issue — staged write (T2). Returns a proposal for the human to
        // confirm in the UI; does NOT create the issue itself. Use after triaging an
        // alert/finding when the user asks to file/track it.
        tool("propose_github_issue", "Propose a GitHub issue for a finding/alert (does NOT create it — returns a proposal the human confirms with a button). Auto-resolves the target repo from the service name and checks for duplicates.", json!({
            "service": { "type": "string", "description": "service the issue is about, e.g. 'eir-gateway', 'mimir-api', 'tyr' — used to pick the repo" },
            "title": { "type": "string", "description": "concise issue title" },
            "body": { "type": "string", "description": "issue body in markdown (summary, evidence, remediation)" }
        })),

        // Phase 5 — GitHub PR review/merge (close the loop: issue→PR→review→merge)
        tool("gh_pr_list", "List GitHub pull requests for a repo (e.g. the draft PRs Muninn opened). Read-only (T2).", json!({
            "repo": { "type": "string", "description": "target repo as 'owner/repo', e.g. 'MegaWiz-Dev-Team/Muninn'" }
        })),
        tool("gh_pr_get", "Get one pull request's metadata + changed files (with diff patches) so you can review it before recommending a merge. Read-only (T2).", json!({
            "repo": { "type": "string", "description": "'owner/repo'" },
            "number": { "type": "integer", "description": "pull request number" }
        })),
        tool("propose_pr_merge", "Propose merging a pull request (does NOT merge — returns a proposal + review info the human confirms with a button). T3 prod write; merge only happens after the click via /api/pulls/merge.", json!({
            "repo": { "type": "string", "description": "'owner/repo'" },
            "number": { "type": "integer", "description": "pull request number to merge" }
        })),

        // propose_active_response — Týr enforcement arm (T3). Proposal only; the send
        // is executed + Thor-gated via POST /api/active-response after a human click.
        tool("propose_active_response", "Propose a Wazuh Active Response (e.g. firewall-drop to block an IP, restart-wazuh, disable-account) on one or more agents. Does NOT execute — returns a proposal the human confirms. T3 enforcement; Thor-gated.", json!({
            "command": { "type": "string", "description": "AR command name, e.g. 'firewall-drop', 'restart-wazuh', 'disable-account'" },
            "agents": { "type": "array", "items": { "type": "string" }, "description": "target agent IDs, e.g. ['001']" }
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
