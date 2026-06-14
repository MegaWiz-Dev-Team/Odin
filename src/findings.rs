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
    #[serde(default)]
    pub plan: String,
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
    if !req.plan.trim().is_empty() {
        // Discord field values cap at 1024 chars.
        let plan = if req.plan.chars().count() > 1000 {
            format!("{}…", req.plan.chars().take(1000).collect::<String>())
        } else {
            req.plan.clone()
        };
        fields.push(json!({ "name": "🧠 Plan", "value": plan, "inline": false }));
    }
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

    let (odin_vote, frigg_vote, odin_reason, frigg_reason) = vote_on_plan(cfg, &req).await;
    let cv = thor::evaluate_consensus(
        &json!({ "odin": odin_vote, "frigg": frigg_vote }).to_string(),
    );
    tracing::info!(
        "🧠 plan-review {} → {} (odin={}, frigg={})",
        req.issue_id, cv.decision, odin_vote, frigg_vote
    );
    let mut conditions: Vec<String> = vec![];
    if cv.decision != "approve" {
        if odin_vote != "approve" && !odin_reason.is_empty() {
            conditions.push(format!("Odin: {}", odin_reason));
        }
        if frigg_vote != "approve" && !frigg_reason.is_empty() {
            conditions.push(format!("Frigg: {}", frigg_reason));
        }
    }

    Json(json!({
        "decision": cv.decision,
        "can_proceed": cv.can_proceed,
        "odin_vote": odin_vote,
        "frigg_vote": frigg_vote,
        "conditions": conditions,
    }))
}

/// Two INDEPENDENT advisor votes on a plan: Odin (feasibility) and Frigg (safety)
/// each get their own Heimdall call with a distinct prompt, run concurrently, so
/// neither sees the other's reasoning. Returns (odin_vote, frigg_vote,
/// odin_reason, frigg_reason). Each fails safe to reject.
async fn vote_on_plan(cfg: &AgentConfig, req: &PlanReviewRequest) -> (String, String, String, String) {
    let odin = one_vote(
        cfg, req, "Odin, the commander",
        "Is the approach FEASIBLE, in-scope, and MINIMAL? Reject scope creep, over-engineering, or a fix that doesn't address the root cause.",
    );
    let frigg = one_vote(
        cfg, req, "Frigg, the advisor",
        "Is it SAFE — small blast radius, easily reversible, free of auth/crypto/data/secret risk? Reject anything hard to revert or touching sensitive paths.",
    );
    let ((ov, or), (fv, fr)) = tokio::join!(odin, frigg);
    (ov, fv, or, fr)
}

/// A single advisor's independent vote — one Heimdall call with its own persona
/// and criteria. Fails safe to ("reject", …).
async fn one_vote(cfg: &AgentConfig, req: &PlanReviewRequest, role: &str, criteria: &str) -> (String, String) {
    let prompt = format!(
        "You are {role}, an Asgard advisor reviewing Muninn's automated fix PLAN before any code is written.\n\
         Issue: {} ({})\nPlan: {}\n\n\
         Judge ONLY this: {criteria}\n\
         Vote approve | conditional | reject — be conservative, prefer conditional/reject when unsure.\n\
         Respond ONLY with JSON: {{\"vote\":\"approve|conditional|reject\",\"reason\":\"one short sentence\"}}",
        req.title, req.repo, req.plan,
    );
    match heimdall_complete(cfg, &prompt).await {
        Some(c) => parse_vote(&c),
        None => ("reject".to_string(), "llm unreachable".to_string()),
    }
}

/// One Heimdall chat completion → the assistant message text (None on error).
async fn heimdall_complete(cfg: &AgentConfig, prompt: &str) -> Option<String> {
    let body = json!({
        "model": cfg.heimdall_model,
        "messages": [{ "role": "user", "content": prompt }],
        "max_tokens": 200,
        "temperature": 0.1
    });
    let client = reqwest::Client::new();
    let mut rb = client.post(format!("{}/v1/chat/completions", cfg.heimdall_url)).json(&body);
    if let Some(k) = &cfg.heimdall_api_key {
        rb = rb.header("Authorization", format!("Bearer {}", k));
    }
    match rb.send().await {
        Ok(r) => {
            let v: Value = r.json().await.unwrap_or_default();
            v.pointer("/choices/0/message/content").and_then(|c| c.as_str()).map(String::from)
        }
        Err(e) => {
            warn!("plan-review LLM unreachable: {}", e);
            None
        }
    }
}

/// Parse an advisor's `{vote, reason}` JSON out of the model text. Fails safe to
/// ("reject", …) — an unknown or missing vote is a reject.
fn parse_vote(content: &str) -> (String, String) {
    let json_str = match (content.find('{'), content.rfind('}')) {
        (Some(a), Some(b)) if b > a => &content[a..=b],
        _ => return ("reject".to_string(), "unparseable vote".to_string()),
    };
    match serde_json::from_str::<Value>(json_str) {
        Ok(v) => {
            let raw = v.get("vote").and_then(|x| x.as_str()).unwrap_or("reject").to_lowercase();
            let vote = match raw.as_str() {
                "approve" => "approve",
                "conditional" => "conditional",
                _ => "reject",
            }
            .to_string();
            (vote, v.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string())
        }
        Err(_) => ("reject".to_string(), "unparseable vote".to_string()),
    }
}

#[cfg(test)]
mod plan_review_tests {
    use super::parse_vote;

    #[test]
    fn parse_vote_normalizes_and_fails_safe() {
        assert_eq!(parse_vote(r#"{"vote":"approve","reason":"ok"}"#), ("approve".to_string(), "ok".to_string()));
        assert_eq!(parse_vote("noise {\"vote\":\"CONDITIONAL\",\"reason\":\"r\"} tail").0, "conditional");
        assert_eq!(parse_vote("garbage no json").0, "reject");
        assert_eq!(parse_vote(r#"{"vote":"maybe"}"#).0, "reject"); // unknown vote → reject
    }
}

/// Tyr anomaly alert about the auto-fix watchdog (governance telemetry breached
/// a Wazuh rule). Odin = the command layer.
#[derive(Deserialize)]
pub struct TyrAlertRequest {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub detail: String,
}

/// POST /api/tyr-alert — Tyr's anomaly detection fires here. Odin posts it to
/// Discord and, for high/critical alerts, COMMANDS Muninn to pause auto-fix
/// (POST muninn /api/control). Tyr watches; Odin commands.
pub async fn tyr_alert_handler(
    State(state): State<ChatState>,
    Json(req): Json<TyrAlertRequest>,
) -> Json<Value> {
    let cfg = &state.cfg;
    let critical = matches!(req.severity.as_str(), "high" | "critical");
    tracing::warn!("🛡️ Tyr alert: {} [{}] {} ({})", req.kind, req.severity, req.message, req.repo);

    if let Some(webhook) = cfg.discord_webhook_url.clone() {
        let color = if critical { 0xFF0000 } else { 0xFFA500 };
        let detail = if req.message.is_empty() { req.detail.clone() } else { req.message.clone() };
        let embed = json!({
            "title": format!("🛡️ Tyr watchdog alert — {}", req.kind),
            "color": color,
            "fields": [
                json!({ "name": "Severity", "value": if req.severity.is_empty() { "unknown".into() } else { req.severity.clone() }, "inline": true }),
                json!({ "name": "Repo", "value": if req.repo.is_empty() { "—".into() } else { req.repo.clone() }, "inline": true }),
                json!({ "name": "Detail", "value": if detail.is_empty() { "—".into() } else { detail }, "inline": false }),
            ],
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        let _ = reqwest::Client::new().post(&webhook).json(&json!({ "embeds": [embed] })).send().await;
    }

    // High/critical → command Muninn to halt auto-fix until a human resumes.
    let mut muninn_paused = false;
    if critical {
        let url = format!("{}/api/control", cfg.muninn_url);
        match reqwest::Client::new().post(&url).json(&json!({ "pause": true })).send().await {
            Ok(r) if r.status().is_success() => {
                muninn_paused = true;
                tracing::warn!("⏸️ Odin commanded Muninn PAUSE on Tyr {} alert", req.severity);
            }
            _ => tracing::warn!("⚠️ Odin could not command Muninn pause"),
        }
    }
    Json(json!({ "received": true, "critical": critical, "muninn_paused": muninn_paused }))
}

#[derive(Deserialize, Default)]
pub struct GovAuditRequest {
    #[serde(default)] pub level: String,
    #[serde(default)] pub detail: String,
    #[serde(default)] pub repo: String,
    #[serde(default)] pub issue_number: u64,
    #[serde(default)] pub kind: String,
    #[serde(default)] pub severity: String,
}

/// POST /api/governance-audit — Muninn reports a Thor governance decision; record
/// it in the `odin-audit` index so the Policy panel shows Thor's L0-L3 verdicts
/// next to Odin's own governance actions. Unprotected (internal Muninn → Odin).
pub async fn governance_audit_handler(
    State(state): State<ChatState>,
    Json(req): Json<GovAuditRequest>,
) -> Json<Value> {
    let action = if req.level.is_empty() {
        format!("muninn:{}", if req.kind.is_empty() { "event".into() } else { req.kind.clone() })
    } else {
        format!("thor:{}", req.level)
    };
    let target = if req.repo.is_empty() {
        "—".to_string()
    } else {
        format!("{}#{}", req.repo, req.issue_number)
    };
    crate::agents::audit_event(
        &reqwest::Client::new(),
        &state.cfg,
        &action,
        json!({ "actor": "muninn", "target": target, "detail": req.detail,
                "severity": req.severity, "kind": req.kind }),
    )
    .await;
    Json(json!({ "ok": true }))
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
