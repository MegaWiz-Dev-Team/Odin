use axum::{extract::{Json, State, Path}, http::StatusCode, response::Html};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;
use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::agents::AgentConfig;
use crate::chat::{run_agent, ChatState};
use crate::report;

// In-memory scan storage: scan_id -> (service, findings, timestamp)
pub struct ScanData {
    pub service: String,
    pub findings: Vec<Value>,
    pub timestamp: String,
}

static SCAN_STORAGE: Lazy<Arc<Mutex<HashMap<String, ScanData>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Deserialize)]
pub struct HuginnFindingsRequest {
    pub service: String,
    pub scan_id: String,
    pub _scan_type: String,
    pub findings: Vec<Value>,
    pub github_issues: Vec<GitHubIssue>,
}

#[derive(Deserialize, Clone)]
pub struct GitHubIssue {
    pub repo: String,
    pub number: u64,
    pub url: String,
    pub finding_title: String,
}

pub async fn huginn_findings_handler(
    State(state): State<ChatState>,
    Json(req): Json<HuginnFindingsRequest>,
) -> Result<(), (StatusCode, String)> {
    let cfg = &state.cfg;

    // Store scan data for report retrieval
    let scan_data = ScanData {
        service: req.service.clone(),
        findings: req.findings.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    let mut storage = SCAN_STORAGE.lock().await;
    storage.insert(req.scan_id.clone(), scan_data);

    let critical_count = req.findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("Critical"))
        .count();
    let high_count = req.findings.iter()
        .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("High"))
        .count();

    let findings_summary = format!(
        "Security scan completed for **{}** ({}): {} critical, {} high severity vulnerabilities",
        req.service, req.scan_id, critical_count, high_count
    );

    let mut context_msg = format!(
        "I analyzed a security scan for service **{}**.\n\n{}",
        req.service, findings_summary
    );

    if !req.github_issues.is_empty() {
        context_msg.push_str("\n\nGitHub issues created:\n");
        for issue in &req.github_issues {
            context_msg.push_str(&format!("- [{}#{}]({}): {}\n", issue.repo, issue.number, issue.url, issue.finding_title));
        }
    }

    context_msg.push_str("\nTop findings:\n");
    for (idx, finding) in req.findings.iter().take(3).enumerate() {
        let severity = finding.get("severity").and_then(|s| s.as_str()).unwrap_or("unknown");
        let title = finding.get("title").and_then(|t| t.as_str()).unwrap_or("unknown");
        let description = finding.get("description").and_then(|d| d.as_str()).unwrap_or("");
        context_msg.push_str(&format!(
            "{}. **[{}]** {} - {}\n",
            idx + 1, severity, title, description
        ));
    }

    let messages = vec![json!({
        "role": "user",
        "content": context_msg
    })];

    match run_agent(&cfg, messages).await {
        Ok((response, _)) => {
            // Format Discord notification with findings and recommendations
            if let Some(webhook_url) = &cfg.discord_webhook_url {
                let _ = send_discord_notification(
                    webhook_url,
                    &req,
                    &response,
                    critical_count,
                    high_count,
                ).await;
            }
            Ok(())
        }
        Err(e) => {
            warn!("failed to analyze findings: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("analysis failed: {}", e)))
        }
    }
}

async fn send_discord_notification(
    webhook_url: &str,
    req: &HuginnFindingsRequest,
    analysis: &str,
    critical_count: usize,
    high_count: usize,
) -> Result<(), String> {
    let client = reqwest::Client::new();

    let color = if critical_count > 0 { 0xFF0000 } else { 0xFF6600 };
    let severity_emoji = if critical_count > 0 { "🔴" } else { "🟠" };

    let mut fields = vec![
        json!({
            "name": "Service",
            "value": req.service,
            "inline": true
        }),
        json!({
            "name": "Scan ID",
            "value": format!("`{}`", req.scan_id),
            "inline": true
        }),
        json!({
            "name": "Severity Count",
            "value": format!("🔴 {}, 🟠 {}", critical_count, high_count),
            "inline": true
        }),
    ];

    if !req.github_issues.is_empty() {
        let issues_str = req.github_issues
            .iter()
            .take(3)
            .map(|i| format!("[{}#{}]({})", i.repo, i.number, i.url))
            .collect::<Vec<_>>()
            .join(", ");
        fields.push(json!({
            "name": "GitHub Issues",
            "value": issues_str,
            "inline": false
        }));
    }

    fields.push(json!({
        "name": "Odin Analysis",
        "value": if analysis.len() > 500 {
            format!("{}…", &analysis[..500])
        } else {
            analysis.to_string()
        },
        "inline": false
    }));

    let embed = json!({
        "title": format!("{} Scan Results: {}", severity_emoji, req.service),
        "color": color,
        "fields": fields,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    let payload = json!({
        "embeds": [embed]
    });

    match client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("✅ Discord notification sent");
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            tracing::warn!("⚠️  Discord returned {}: {}", status, text);
            Ok(())
        }
        Err(e) => {
            tracing::warn!("❌ Discord notification failed: {}", e);
            Ok(())
        }
    }
}

/// Approval request from Muninn (Thor rated a finding L2/L3 — needs human sign-off).
#[derive(Deserialize)]
pub struct MuninnApprovalRequest {
    pub issue_id: String,
    pub repo: String,
    #[serde(default)]
    pub issue_number: u64,
    #[serde(default)]
    pub title: String,
    pub level: String,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub approve_url: Option<String>,
    #[serde(default)]
    pub reject_url: Option<String>,
}

/// POST /api/approvals — Muninn asks Odin to get a human to approve a fix.
/// Odin posts it to Discord (with approve/reject links). A human then approves —
/// in Discord, or by having Odin call the `muninn_approve_fix` tool — which
/// commands Muninn back to run the fix.
pub async fn muninn_approval_handler(
    State(state): State<ChatState>,
    Json(req): Json<MuninnApprovalRequest>,
) -> Result<(), (StatusCode, String)> {
    let cfg = &state.cfg;
    tracing::info!("🗡️ Muninn approval request: {} {} ({})", req.issue_id, req.level, req.repo);

    let Some(webhook_url) = cfg.discord_webhook_url.clone() else {
        warn!("DISCORD_WEBHOOK_URL not set — approval {} not posted to Discord", req.issue_id);
        return Ok(());
    };

    let color = if req.level == "L3" { 0xFF0000 } else { 0xFFA500 };
    let mut fields = vec![
        json!({ "name": "Repo", "value": format!("{}#{}", req.repo, req.issue_number), "inline": true }),
        json!({ "name": "Risk", "value": req.level, "inline": true }),
        json!({
            "name": "Why",
            "value": if req.reasons.is_empty() { "—".to_string() } else { req.reasons.join("\n") },
            "inline": false
        }),
    ];
    let action = match (&req.approve_url, &req.reject_url) {
        (Some(a), Some(r)) => format!("✅ [Approve]({})  ·  ❌ [Reject]({})", a, r),
        (Some(a), None) => format!("✅ [Approve]({})", a),
        _ => format!("Approve via Odin: `muninn_approve_fix {}`", req.issue_id),
    };
    fields.push(json!({ "name": "Action", "value": action, "inline": false }));

    let embed = json!({
        "title": format!("⚡ Muninn fix needs approval — {}", req.title),
        "color": color,
        "fields": fields,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    let payload = json!({ "embeds": [embed] });

    let client = reqwest::Client::new();
    match client.post(&webhook_url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("✅ Approval request posted to Discord: {}", req.issue_id);
        }
        Ok(resp) => warn!("⚠️ Discord returned {} for approval {}", resp.status(), req.issue_id),
        Err(e) => warn!("❌ Discord approval post failed: {}", e),
    }
    Ok(())
}

/// Muninn's fix-plan review request (Odin+Frigg advisory consensus).
#[derive(Deserialize)]
pub struct PlanReviewRequest {
    pub issue_id: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub plan: Value,
}

/// POST /api/plan-review — Muninn asks the Odin+Frigg advisory panel to review a
/// fix plan BEFORE any code is written. Odin (commander) judges feasibility,
/// Frigg (advisor) judges safety; the two votes are combined by Thor's consensus
/// policy. Fails safe to `reject` on any LLM error.
pub async fn plan_review_handler(
    State(state): State<ChatState>,
    Json(req): Json<PlanReviewRequest>,
) -> Json<Value> {
    let cfg = &state.cfg;
    tracing::info!("🧠 plan-review for {} ({})", req.issue_id, req.repo);

    let (odin_vote, frigg_vote, reason) = vote_on_plan(cfg, &req).await;
    let cv = thor::evaluate_consensus(
        &json!({ "odin": odin_vote, "frigg": frigg_vote }).to_string(),
    );
    tracing::info!(
        "🧠 plan-review {} → {} (odin={}, frigg={})",
        req.issue_id, cv.decision, odin_vote, frigg_vote
    );
    let conditions: Vec<String> =
        if cv.decision != "approve" && !reason.is_empty() { vec![reason] } else { vec![] };

    Json(json!({
        "decision": cv.decision,
        "can_proceed": cv.can_proceed,
        "odin_vote": odin_vote,
        "frigg_vote": frigg_vote,
        "conditions": conditions,
    }))
}

/// One Heimdall call that returns the Odin + Frigg votes on a plan. Fails safe to
/// (reject, reject) on any error or unparseable output.
async fn vote_on_plan(cfg: &AgentConfig, req: &PlanReviewRequest) -> (String, String, String) {
    let prompt = format!(
        "Two Asgard advisors review Muninn's automated fix PLAN before any code is written.\n\
         Issue: {} ({})\nPlan: {}\n\n\
         Odin (commander) judges: is the approach feasible, in-scope, and minimal?\n\
         Frigg (advisor) judges: is it SAFE — small blast radius, reversible, no auth/crypto/data risk?\n\
         Each votes approve | conditional | reject. Be conservative — prefer conditional/reject when unsure.\n\
         Respond ONLY with JSON: {{\"odin\":\"approve|conditional|reject\",\"frigg\":\"approve|conditional|reject\",\"reason\":\"one short sentence\"}}",
        req.title, req.repo, req.plan
    );
    let body = json!({
        "model": cfg.heimdall_model,
        "messages": [{ "role": "user", "content": prompt }],
        "max_tokens": 300,
        "temperature": 0.1
    });
    let client = reqwest::Client::new();
    let mut rb = client.post(format!("{}/v1/chat/completions", cfg.heimdall_url)).json(&body);
    if let Some(k) = &cfg.heimdall_api_key {
        rb = rb.header("Authorization", format!("Bearer {}", k));
    }
    let content = match rb.send().await {
        Ok(r) => {
            let v: Value = r.json().await.unwrap_or_default();
            v.pointer("/choices/0/message/content").and_then(|c| c.as_str()).unwrap_or("").to_string()
        }
        Err(e) => {
            warn!("plan-review LLM unreachable: {}", e);
            return ("reject".into(), "reject".into(), "llm unreachable".into());
        }
    };
    let json_str = match (content.find('{'), content.rfind('}')) {
        (Some(a), Some(b)) if b > a => &content[a..=b],
        _ => return ("reject".into(), "reject".into(), "unparseable vote".into()),
    };
    match serde_json::from_str::<Value>(json_str) {
        Ok(v) => {
            let norm = |k: &str| -> String {
                let s = v.get(k).and_then(|x| x.as_str()).unwrap_or("reject").to_lowercase();
                match s.as_str() {
                    "approve" => "approve".into(),
                    "conditional" => "conditional".into(),
                    _ => "reject".into(),
                }
            };
            (norm("odin"), norm("frigg"), v.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string())
        }
        Err(_) => ("reject".into(), "reject".into(), "unparseable vote".into()),
    }
}

// GET /api/reports/:scan_id - Returns ISO 27001 security report as HTML
pub async fn get_report_html(
    Path(scan_id): Path<String>,
) -> Result<Html<String>, (StatusCode, String)> {
    let storage = SCAN_STORAGE.lock().await;

    let scan_data = storage
        .get(&scan_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Scan {} not found", scan_id)))?;

    let security_report = report::generate_iso_report(
        &scan_id,
        &scan_data.service,
        &scan_data.findings,
    );

    let html = report::render_html_report(&security_report);

    Ok(Html(html))
}
