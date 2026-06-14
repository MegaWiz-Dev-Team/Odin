mod agents;
mod bridge;
mod chat;
mod discord;
mod findings;
mod policy;
mod report;

use axum::{
    extract::{Json, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::info;

use crate::agents::AgentConfig;
use crate::chat::ChatState;

/// Per-process random bearer token, generated fresh on each startup.
/// Issued by /api/auth/login (after credential check) and required by the
/// auth middleware on every protected /api route. Uses the OS RNG that seeds
/// std's RandomState — no extra crate needed.
static SESSION_TOKEN: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    use std::hash::{BuildHasher, Hasher};
    let mut s = String::with_capacity(64);
    for _ in 0..4 {
        let h = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        s.push_str(&format!("{:016x}", h));
    }
    s
});

/// Auth middleware — requires `Authorization: Bearer <SESSION_TOKEN>` on
/// protected routes. Anything else → 401.
async fn require_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    let ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t == SESSION_TOKEN.as_str())
        .unwrap_or(false);
    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}


async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    let user = payload.username.unwrap_or_default();
    let pass = payload.password.unwrap_or_default();

    // Credentials come from env (ODIN_USER / ODIN_PASS); fall back to admin/admin
    // for local dev only. Set these in the launch env — never hardcode in source.
    let expected_user = std::env::var("ODIN_USER").unwrap_or_else(|_| "admin".into());
    let expected_pass = std::env::var("ODIN_PASS").unwrap_or_else(|_| "admin".into());

    if user == expected_user && pass == expected_pass {
        let response = LoginResponse {
            token: SESSION_TOKEN.clone(),
        };
        (StatusCode::OK, Json(response)).into_response()
    } else {
        let response = ErrorResponse {
            error: "Invalid username or password".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(response)).into_response()
    }
}

/// Server-side health check for endpoints the browser can't reach directly
/// (Tyr uses self-signed TLS + basic-auth; Odin's http_client already accepts
/// invalid certs). Returns a flat map of {key: bool}.
async fn health_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();

    // Tyr indexer (OpenSearch) — needs basic auth, success = 2xx
    let tyr_indexer = client
        .get(format!("{}/_cluster/health", cfg.tyr_indexer_url))
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    // Tyr manager (Wazuh API) — any HTTP response (even 401) means it's alive
    let tyr_manager = client
        .get(format!("{}/", cfg.tyr_url))
        .send()
        .await
        .is_ok();

    // Heimdall LLM gateway
    let heimdall = client
        .get(format!("{}/health", cfg.heimdall_url))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let probe = |url: String| {
        let c = client.clone();
        async move { c.get(url).send().await.map(|r| r.status().is_success() || r.status().as_u16() == 401).unwrap_or(false) }
    };
    let vardr   = probe(format!("{}/health",   cfg.vardr_url)).await;
    let huginn  = probe(format!("{}/health",   cfg.huginn_url)).await;
    let muninn  = probe(format!("{}/health",   cfg.muninn_url)).await;
    let forseti = probe(format!("{}/api/runs?limit=1", cfg.forseti_url)).await;
    let mjolnir = probe(format!("{}/healthz",  cfg.mjolnir_url)).await;
    let loki    = probe(format!("{}/health",   cfg.loki_url)).await;
    let ratatoskr = probe(format!("{}/healthz", cfg.ratatoskr_url)).await;
    let laminar   = probe(format!("{}/health",  cfg.laminar_url)).await;

    Json(serde_json::json!({
        "odin": true,
        "tyr_indexer": tyr_indexer,
        "tyr_manager": tyr_manager,
        "heimdall": heimdall,
        "vardr": vardr,
        "huginn": huginn,
        "muninn": muninn,
        "forseti": forseti,
        "mjolnir": mjolnir,
        "loki": loki,
        "ratatoskr": ratatoskr,
        "laminar": laminar,
    }))
}

/// Proxy Muninn's tracked issues through Odin (browser can't reach Muninn's
/// ClusterIP / localhost-only port-forward, esp. over Tailscale). Returns the
/// raw JSON array, or [] on any failure so the UI degrades gracefully.
/// Proxy Muninn's fix-pipeline progress to the dashboard (Odin UI).
async fn progress_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    match client.get(format!("{}/api/progress", cfg.muninn_url)).send().await.ok() {
        Some(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => Json(v),
            Err(_) => Json(serde_json::json!({})),
        },
        None => Json(serde_json::json!({})),
    }
}

async fn issues_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let body = client
        .get(format!("{}/api/issues", cfg.muninn_url))
        .send()
        .await
        .ok();
    match body {
        Some(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => Json(v),
            Err(_) => Json(serde_json::json!([])),
        },
        None => Json(serde_json::json!([])),
    }
}

/// Proxy Muninn's config (agent / model / mode / watched repos) through Odin.
async fn config_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let body = client
        .get(format!("{}/api/config", cfg.muninn_url))
        .send()
        .await
        .ok();
    match body {
        Some(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => Json(v),
            Err(_) => Json(serde_json::json!({})),
        },
        None => Json(serde_json::json!({})),
    }
}

/// One-page inspection roll-up: a status per SOC domain (Availability /
/// Vulnerability / Remediation / Detection / Governance), each best-effort so one
/// unreachable backend never fails the whole panel.
async fn checks_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    use serde_json::json;
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let mut checks: Vec<serde_json::Value> = Vec::new();

    // ── Availability ──
    let svcs: [(&str, String); 5] = [
        ("Heimdall", format!("{}/health", cfg.heimdall_url)),
        ("Huginn", format!("{}/health", cfg.huginn_url)),
        ("Muninn", format!("{}/health", cfg.muninn_url)),
        ("Vardr", format!("{}/health", cfg.vardr_url)),
        ("Loki", format!("{}/health", cfg.loki_url)),
    ];
    let mut up = 0u32;
    for (_n, u) in &svcs {
        if client.get(u).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            up += 1;
        }
    }
    let total = svcs.len() as u32;
    checks.push(json!({
        "domain": "Availability", "tool": "Vardr",
        "status": if up == total { "ok" } else if up == 0 { "fail" } else { "warn" },
        "metric": format!("{}/{} up", up, total), "detail": "core services responding"
    }));

    // ── Vulnerability (Huginn) ──
    let v = match client.get(format!("{}/api/stats", cfg.huginn_url)).send().await.ok() {
        Some(r) => r.json::<serde_json::Value>().await.ok(),
        None => None,
    };
    match v {
        Some(s) => {
            let sev = s.get("by_severity").cloned().unwrap_or(json!({}));
            let crit = sev.get("critical").and_then(|x| x.as_i64()).unwrap_or(0);
            let high = sev.get("high").and_then(|x| x.as_i64()).unwrap_or(0);
            let tf = s.get("total_findings").and_then(|x| x.as_i64()).unwrap_or(0);
            checks.push(json!({
                "domain": "Vulnerability", "tool": "Huginn",
                "status": if crit > 0 { "fail" } else if high > 0 { "warn" } else { "ok" },
                "metric": format!("{} findings", tf), "detail": format!("{} critical / {} high", crit, high)
            }));
        }
        None => checks.push(json!({"domain":"Vulnerability","tool":"Huginn","status":"unknown","metric":"—","detail":"stats unavailable"})),
    }

    // ── Remediation (Muninn) ──
    let r = match client.get(format!("{}/api/stats", cfg.muninn_url)).send().await.ok() {
        Some(x) => x.json::<serde_json::Value>().await.ok(),
        None => None,
    };
    match r {
        Some(s) => {
            let ti = s.get("total_issues").and_then(|x| x.as_i64()).unwrap_or(0);
            let tf = s.get("total_fixes").and_then(|x| x.as_i64()).unwrap_or(0);
            checks.push(json!({"domain":"Remediation","tool":"Muninn","status":"ok","metric":format!("{} issues",ti),"detail":format!("{} fixes",tf)}));
        }
        None => checks.push(json!({"domain":"Remediation","tool":"Muninn","status":"unknown","metric":"—","detail":"stats unavailable"})),
    }

    // ── Detection (Tyr indexer) ──
    let det = client
        .get(format!("{}/_cluster/health", cfg.tyr_indexer_url))
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .send().await.map(|r| r.status().is_success()).unwrap_or(false);
    checks.push(json!({"domain":"Detection","tool":"Tyr","status": if det {"ok"} else {"fail"},"metric": if det {"reachable"} else {"down"},"detail":"SIEM indexer"}));

    // ── Governance (Thor audit trail) ──
    let g = match client
        .get(format!("{}/odin-audit/_count", cfg.tyr_indexer_url))
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .send().await.ok()
    {
        Some(x) => x.json::<serde_json::Value>().await.ok(),
        None => None,
    };
    let gc = g.and_then(|x| x.get("count").and_then(|c| c.as_i64())).unwrap_or(-1);
    checks.push(json!({
        "domain":"Governance","tool":"Thor","status": if gc >= 0 {"ok"} else {"unknown"},
        "metric": if gc >= 0 { format!("{} decisions", gc) } else { "—".to_string() }, "detail":"policy audit trail"
    }));

    Json(json!({ "checks": checks }))
}

#[derive(Deserialize)]
struct BatchStatusRequest {
    scans: Vec<String>,
}

/// Aggregate Huginn batch progress. Given the scan ids returned by huginn_batch_scan,
/// fetch Huginn's scan list once and tally status + findings for just those ids — so
/// the chat can render a live progress bar without the browser polling N scans
/// individually. batch_id isn't persisted on scans, so the id set is the grouping key.
async fn huginn_batch_status(
    State(state): State<ChatState>,
    Json(req): Json<BatchStatusRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let want: std::collections::HashSet<String> = req.scans.into_iter().collect();
    let total = want.len();

    let list = client
        .get(format!("{}/api/scans?limit=2000", cfg.huginn_url))
        .send()
        .await
        .ok();
    let scans: Vec<serde_json::Value> = match list {
        Some(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => v
                .as_array()
                .cloned()
                .or_else(|| v.get("scans").and_then(|s| s.as_array()).cloned())
                .unwrap_or_default(),
            Err(_) => vec![],
        },
        None => vec![],
    };

    let (mut completed, mut failed, mut running, mut findings) = (0usize, 0usize, 0usize, 0u64);
    let mut services: Vec<serde_json::Value> = Vec::new();
    for s in &scans {
        let id = s.get("scan_id").and_then(|x| x.as_str()).unwrap_or("");
        if !want.contains(id) {
            continue;
        }
        let status = s.get("status").and_then(|x| x.as_str()).unwrap_or("");
        let fc = s.get("finding_count").and_then(|x| x.as_u64()).unwrap_or(0);
        findings += fc;
        match status {
            "completed" => completed += 1,
            "failed" => failed += 1,
            "running" => running += 1,
            _ => {}
        }
        services.push(serde_json::json!({
            "target": s.get("target"),
            "scan_type": s.get("scan_type"),
            "status": status,
            "finding_count": fc,
        }));
    }
    // Any requested id not yet present in the list is still queued (pending).
    let known = completed + failed + running;
    let pending = total.saturating_sub(known);
    let percent = if total == 0 { 0 } else { ((completed + failed) * 100) / total };
    let done = total > 0 && (completed + failed) >= total;

    Json(serde_json::json!({
        "total": total,
        "completed": completed,
        "failed": failed,
        "running": running,
        "pending": pending,
        "findings": findings,
        "percent": percent,
        "done": done,
        "services": services,
    }))
}

/// Surface recent Thor/governance decisions (the `odin-audit` index) through Odin —
/// pr_merge / pr_merge_denied, create / *_denied_by_thor, active_response(_denied),
/// tyr_bridge_create_issue, etc. Server-side (browser/Tailscale can't reach the
/// indexer). Fetches match_all and sorts newest-first in-process (rfc3339 `ts`
/// sorts lexicographically) to avoid the indexer text/fielddata sort gotcha.
async fn audit_proxy(State(state): State<ChatState>) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let url = format!("{}/odin-audit/_search", cfg.tyr_indexer_url);
    let q = serde_json::json!({ "size": 100, "query": { "match_all": {} } });
    let resp = client
        .post(&url)
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .json(&q)
        .send()
        .await;
    let mut events: Vec<serde_json::Value> = match resp {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => v
                .pointer("/hits/hits")
                .and_then(|h| h.as_array())
                .map(|a| a.iter().filter_map(|h| h.get("_source").cloned()).collect())
                .unwrap_or_default(),
            Err(_) => vec![],
        },
        Err(_) => vec![],
    };
    events.sort_by(|a, b| {
        let ta = a.get("ts").and_then(|x| x.as_str()).unwrap_or("");
        let tb = b.get("ts").and_then(|x| x.as_str()).unwrap_or("");
        tb.cmp(ta) // newest first
    });
    events.truncate(50);
    Json(serde_json::json!({ "events": events }))
}

#[derive(Deserialize)]
struct SaveReportRequest {
    title: Option<String>,
    content: String,
}

/// Save a chat report into the Wazuh indexer as an audit record
/// (`odin-reports-YYYY.MM` index). Server-side so the browser/Tailscale never
/// needs indexer access. Returns the doc id on success.
async fn save_report(
    State(state): State<ChatState>,
    Json(req): Json<SaveReportRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();
    let title = req.title.unwrap_or_else(|| "Odin report".to_string());
    // index name carries no date math here (clusters reject dynamic dates in path);
    // use a fixed rolling index — OpenSearch ISM/aliases can roll it later.
    let url = format!("{}/odin-reports/_doc?refresh=wait_for", cfg.tyr_indexer_url);
    let body = serde_json::json!({
        "title": title,
        "content": req.content,
        "source": "odin-chat",
    });
    let resp = client
        .post(&url)
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let v: serde_json::Value = r.json().await.unwrap_or_default();
            Json(serde_json::json!({
                "status": "saved",
                "id": v.get("_id"),
                "index": "odin-reports"
            })).into_response()
        }
        Ok(r) => {
            let code = r.status().as_u16();
            (StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("indexer {}", code)}))).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("indexer unreachable: {}", e)}))).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateIssueRequest {
    service: Option<String>,
    repo: Option<String>,        // explicit owner/repo overrides service mapping
    title: String,
    body: Option<String>,
}

#[derive(Deserialize)]
struct MergePrRequest {
    repo: String,                // "owner/repo"
    number: u64,
    method: Option<String>,      // merge | squash | rebase (default squash)
}

#[derive(Deserialize)]
struct ActiveResponseRequest {
    command: String,
    agents: Vec<String>,
    #[serde(default)]
    arguments: Vec<String>,
}

/// HITL confirm endpoint — the human clicked "Create" on a proposed issue.
/// Dedups, creates the GitHub issue server-side (token never reaches the browser),
/// records the fingerprint, and audits. This is the only place an issue is created.
async fn create_issue(
    State(state): State<ChatState>,
    Json(req): Json<CreateIssueRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();

    // Preserve the explicit 503 contract: no token → service unavailable (propose
    // still works; create is blocked — safe default).
    if cfg.github_token.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "GITHUB_TOKEN not configured on Odin"}))).into_response();
    }
    let repo = req.repo.clone().unwrap_or_else(|| {
        crate::agents::service_to_repo(req.service.as_deref().unwrap_or(""))
    });
    let body = req.body.clone().unwrap_or_default();

    let outcome = crate::agents::create_issue_core(
        &client, &cfg, &repo, &req.title, &body, &["odin", "auto-triage"],
    ).await;

    match outcome.status {
        "created" | "duplicate" => Json(serde_json::json!({
            "status": outcome.status,
            "issue_url": outcome.issue_url,
            "repo": outcome.repo,
            "fingerprint": outcome.fingerprint,
        })).into_response(),
        "denied" => (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "status": "denied_by_thor",
            "error": outcome.error.unwrap_or_else(|| "denied by policy".into()),
            "repo": outcome.repo,
        }))).into_response(),
        _ => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": outcome.error.unwrap_or_else(|| "github error".into()),
            "repo": outcome.repo,
        }))).into_response(),
    }
}

/// HITL confirm endpoint (T3) — the human clicked "Merge" on a proposed PR merge.
/// Merges server-side via the GitHub API and audits the action. This is the only
/// place a PR is actually merged.
async fn merge_pr(
    State(state): State<ChatState>,
    Json(req): Json<MergePrRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();

    if cfg.github_token.is_none() {
        return (StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "GITHUB_TOKEN not configured on Odin"}))).into_response();
    }

    // Thor policy gate (Regorus/Rego, via the `thor` crate) — evaluate the PR
    // against merge policy BEFORE merging.
    let pr = crate::agents::gh_pr_get(&client, &cfg, &req.repo, req.number).await;
    let policy = crate::policy::MergePolicy::from_env();
    let verdict = crate::policy::check_merge(&policy, &pr);
    if !verdict.allow {
        crate::agents::audit_event(&client, &cfg, "pr_merge_denied", serde_json::json!({
            "repo": req.repo, "number": req.number, "gate": "thor",
            "violations": verdict.violations, "warnings": verdict.warnings,
        })).await;
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "status": "denied_by_thor",
            "violations": verdict.violations,
            "warnings": verdict.warnings,
        }))).into_response();
    }
    if policy.dry_run {
        crate::agents::audit_event(&client, &cfg, "pr_merge_dry_run", serde_json::json!({
            "repo": req.repo, "number": req.number, "gate": "thor", "warnings": verdict.warnings,
        })).await;
        return Json(serde_json::json!({
            "status": "dry_run", "would_merge": true,
            "repo": req.repo, "number": req.number, "warnings": verdict.warnings,
        })).into_response();
    }

    let method = req.method.as_deref().unwrap_or("squash");
    let outcome = crate::agents::merge_pr_core(&client, &cfg, &req.repo, req.number, method).await;

    crate::agents::audit_event(&client, &cfg, "pr_merge", serde_json::json!({
        "repo": req.repo, "number": req.number, "method": method,
        "result": outcome.get("status"), "error": outcome.get("error"),
        "thor_warnings": verdict.warnings,
    })).await;

    let ok = outcome.get("status").and_then(|s| s.as_str()) == Some("merged");
    if ok {
        Json(outcome).into_response()
    } else {
        (StatusCode::BAD_GATEWAY, Json(outcome)).into_response()
    }
}

/// HITL confirm endpoint (T3) — send a Wazuh Active Response after a human clicks.
/// Thor-gated (command allowlist + agent-target policy), then dispatched to the
/// Wazuh manager API, and audited. The enforcement counterpart to Odin's read tools.
async fn active_response(
    State(state): State<ChatState>,
    Json(req): Json<ActiveResponseRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let client = crate::agents::http_client();

    // Thor policy gate
    let policy = crate::policy::ActiveResponsePolicy::from_env();
    let verdict = crate::policy::check_active_response(&policy, &req.command, &req.agents);
    if !verdict.allow {
        crate::agents::audit_event(&client, &cfg, "active_response_denied", serde_json::json!({
            "command": req.command, "agents": req.agents, "gate": "thor",
            "violations": verdict.violations, "warnings": verdict.warnings,
        })).await;
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "status": "denied_by_thor",
            "violations": verdict.violations,
            "warnings": verdict.warnings,
        }))).into_response();
    }

    let outcome = crate::agents::active_response_core(
        &client, &cfg, &req.command, &req.agents, &req.arguments,
    ).await;
    crate::agents::audit_event(&client, &cfg, "active_response", serde_json::json!({
        "command": req.command, "agents": req.agents,
        "result": outcome.get("status"), "thor_warnings": verdict.warnings,
    })).await;

    let ok = outcome.get("status").and_then(|s| s.as_str()) == Some("sent");
    if ok {
        Json(outcome).into_response()
    } else {
        (StatusCode::BAD_GATEWAY, Json(outcome)).into_response()
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Serve static files (Dashboard SPA) and fallback to index.html
    let static_dir = ServeDir::new("static")
        .not_found_service(ServeFile::new("static/index.html"));

    // Shared state for chat (agent endpoint config from env)
    let cfg = Arc::new(AgentConfig::from_env());
    let chat_state = ChatState {
        cfg: cfg.clone(),
    };

    // Protected API — every route here requires a valid Bearer token from login.
    let protected = Router::new()
        .route("/api/chat", post(chat::chat_handler))
        .route("/api/health-proxy", axum::routing::get(health_proxy))
        .route("/api/issues", axum::routing::get(issues_proxy))
        .route("/api/audit", axum::routing::get(audit_proxy))
        .route("/api/checks", axum::routing::get(checks_proxy))
        .route("/api/issues/create", post(create_issue))
        .route("/api/pulls/merge", post(merge_pr))
        .route("/api/active-response", post(active_response))
        .route("/api/huginn/batch-status", post(huginn_batch_status))
        .route("/api/reports/save", post(save_report))
        .route("/api/config", axum::routing::get(config_proxy))
        .route("/api/muninn-progress", axum::routing::get(progress_proxy))
        .layer(middleware::from_fn(require_auth));

    // Public — login (issues the token), the Huginn webhook (machine-to-machine),
    // report HTML links, and the static dashboard UI.
    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/huginn-findings", post(findings::huginn_findings_handler))
        .route("/api/approvals", post(findings::muninn_approval_handler))
        .route("/api/plan-review", post(findings::plan_review_handler))
        .route("/api/tyr-alert", post(findings::tyr_alert_handler))
        .route("/api/reports/{scan_id}", axum::routing::get(findings::get_report_html))
        .merge(protected)
        .with_state(chat_state)
        .fallback_service(static_dir)
        .layer(TraceLayer::new_for_http());

    // Spawn Discord bot in background if token is configured
    let discord_cfg = cfg.clone();
    tokio::spawn(async move {
        discord::start_bot(discord_cfg).await;
    });

    // Spawn Týr alert→issue bridge (no-op unless TYR_AUTO_BRIDGE=true)
    let bridge_cfg = cfg.clone();
    tokio::spawn(async move {
        bridge::start_alert_bridge(bridge_cfg).await;
    });

    // Run our app
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("🏛️ Odin API Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
