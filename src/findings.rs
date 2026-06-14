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
    // Huginn sends `scan_type`. It ALSO sends a transitional `_scan_type` key for
    // back-compat with the pre-rename receiver; serde silently ignores that
    // unknown key. Do NOT alias `_scan_type` here — accepting both keys as the
    // same field makes serde reject the real (dual-key) payload as a duplicate
    // field → 422.
    #[serde(default)]
    pub scan_type: String,
    #[serde(default)]
    pub findings: Vec<Value>,
    #[serde(default)]
    pub github_issues: Vec<GitHubIssue>,
    // Huginn v0.5.0+ sends authoritative, full-breakdown counts for the WHOLE
    // scan (not just the ≥threshold findings carried in `findings`). Prefer these
    // over re-deriving from the lowercased finding strings.
    #[serde(default)]
    pub finding_count: Option<u64>,
    #[serde(default)]
    pub severity_counts: Option<SeverityCounts>,
    #[serde(default)]
    pub notify_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct SeverityCounts {
    #[serde(default)]
    pub critical: u64,
    #[serde(default)]
    pub high: u64,
    #[serde(default)]
    pub medium: u64,
    #[serde(default)]
    pub low: u64,
    #[serde(default)]
    pub info: u64,
}

impl SeverityCounts {
    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Highest severity present — drives card colour / emoji.
    fn top(&self) -> &'static str {
        if self.critical > 0 {
            "critical"
        } else if self.high > 0 {
            "high"
        } else if self.medium > 0 {
            "medium"
        } else if self.low > 0 {
            "low"
        } else if self.info > 0 {
            "info"
        } else {
            "clean"
        }
    }
}

/// Fallback when Huginn didn't send `severity_counts` (pre-0.5.0): derive counts
/// case-insensitively from the findings array. The old handler matched
/// `== Some("Critical")` exactly, so it always counted 0 against Huginn's
/// lowercase "critical"/"high" — this is the bug that made every card read 0/0.
fn derive_counts(findings: &[Value]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for f in findings {
        match f
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str()
        {
            "critical" => c.critical += 1,
            "high" => c.high += 1,
            "medium" => c.medium += 1,
            "low" => c.low += 1,
            _ => c.info += 1,
        }
    }
    c
}

/// UTF-8-safe truncation (Odin analysis is often Thai — slicing on a byte index
/// mid-codepoint would panic and drop the whole notification).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
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
    {
        let mut storage = SCAN_STORAGE.lock().await;
        storage.insert(req.scan_id.clone(), scan_data);
    }

    // Prefer Huginn's authoritative full-breakdown counts; fall back to deriving
    // (case-insensitively) from findings for older Huginn payloads.
    let counts = req
        .severity_counts
        .clone()
        .unwrap_or_else(|| derive_counts(&req.findings));
    let total = req.finding_count.unwrap_or_else(|| counts.total());

    // Clean completion → informational green card, skip the (costly) LLM call.
    if total == 0 {
        if let Some(webhook_url) = &cfg.discord_webhook_url {
            let _ = send_completion_card(webhook_url, &req, &counts, total, None).await;
        }
        return Ok(());
    }

    // Findings present → run the analysis agent, then post a card carrying the
    // FULL severity breakdown + the analysis.
    let context_msg = build_context(&req, &counts, total);
    let messages = vec![json!({ "role": "user", "content": context_msg })];

    match run_agent(cfg, messages).await {
        Ok((response, _)) => {
            if let Some(webhook_url) = &cfg.discord_webhook_url {
                let _ = send_completion_card(webhook_url, &req, &counts, total, Some(&response)).await;
            }
            Ok(())
        }
        Err(e) => {
            warn!("failed to analyze findings: {}", e);
            // Still surface the completion to Discord even if analysis failed.
            if let Some(webhook_url) = &cfg.discord_webhook_url {
                let _ = send_completion_card(webhook_url, &req, &counts, total, None).await;
            }
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("analysis failed: {}", e)))
        }
    }
}

/// Build the LLM context message from the scan summary + top findings.
fn build_context(req: &HuginnFindingsRequest, counts: &SeverityCounts, total: u64) -> String {
    let mut msg = format!(
        "I analyzed a security scan for service **{}** (scan `{}`).\n\n\
         Result: {} finding(s) — 🔴 {} critical, 🟠 {} high, 🟡 {} medium, 🟢 {} low, ⚪ {} info.",
        req.service,
        req.scan_id,
        total,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    );

    if !req.github_issues.is_empty() {
        msg.push_str("\n\nGitHub issues created:\n");
        for issue in &req.github_issues {
            msg.push_str(&format!(
                "- [{}#{}]({}): {}\n",
                issue.repo, issue.number, issue.url, issue.finding_title
            ));
        }
    }

    msg.push_str("\nTop findings:\n");
    for (idx, finding) in req.findings.iter().take(3).enumerate() {
        let severity = finding.get("severity").and_then(|s| s.as_str()).unwrap_or("unknown");
        let title = finding.get("title").and_then(|t| t.as_str()).unwrap_or("unknown");
        let description = finding.get("description").and_then(|d| d.as_str()).unwrap_or("");
        msg.push_str(&format!(
            "{}. **[{}]** {} - {}\n",
            idx + 1,
            severity,
            title,
            description
        ));
    }
    msg
}

async fn send_completion_card(
    webhook_url: &str,
    req: &HuginnFindingsRequest,
    counts: &SeverityCounts,
    total: u64,
    analysis: Option<&str>,
) -> Result<(), String> {
    let client = reqwest::Client::new();

    // Colour/emoji by the highest severity present (green when clean).
    let (emoji, color) = match counts.top() {
        "critical" => ("🔴", 0xFF0000),
        "high" => ("🟠", 0xFF6600),
        "medium" => ("🟡", 0xFFAA00),
        "low" => ("🟢", 0xFFFF00),
        "info" => ("ℹ️", 0x0099CC),
        _ => ("✅", 0x2ECC71), // clean
    };

    let title = if total == 0 {
        format!("✅ Scan Clean: {}", req.service)
    } else {
        format!("{} Scan Results: {} — {} finding(s)", emoji, req.service, total)
    };

    // Full breakdown + total — never hide medium/low/info behind a crit/high-only badge.
    let severity_value = format!(
        "🔴 {} · 🟠 {} · 🟡 {} · 🟢 {} · ⚪ {}  (total {})",
        counts.critical, counts.high, counts.medium, counts.low, counts.info, total
    );

    let mut fields = vec![
        json!({ "name": "Service", "value": req.service, "inline": true }),
        json!({ "name": "Scan ID", "value": format!("`{}`", req.scan_id), "inline": true }),
    ];
    if let Some(level) = &req.notify_level {
        fields.push(json!({ "name": "Level", "value": level, "inline": true }));
    }
    fields.push(json!({ "name": "Severity Count", "value": severity_value, "inline": false }));

    if !req.github_issues.is_empty() {
        let issues_str = req
            .github_issues
            .iter()
            .take(3)
            .map(|i| format!("[{}#{}]({})", i.repo, i.number, i.url))
            .collect::<Vec<_>>()
            .join(", ");
        fields.push(json!({ "name": "GitHub Issues", "value": issues_str, "inline": false }));
    }

    if let Some(analysis) = analysis {
        fields.push(json!({
            "name": "Odin Analysis",
            "value": truncate(analysis, 500),
            "inline": false
        }));
    }

    let embed = json!({
        "title": title,
        "color": color,
        "fields": fields,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    let payload = json!({ "embeds": [embed] });

    match client.post(webhook_url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("✅ Discord notification sent ({} findings)", total);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_counts_is_case_insensitive() {
        // Huginn sends lowercase severities — the old `== Some("Critical")` check
        // counted these as 0. Verify the case-insensitive derivation is correct.
        let findings = vec![
            json!({"severity": "critical"}),
            json!({"severity": "High"}),
            json!({"severity": "medium"}),
            json!({"severity": "medium"}),
            json!({"severity": "low"}),
            json!({"severity": "info"}),
        ];
        let c = derive_counts(&findings);
        assert_eq!(c.critical, 1);
        assert_eq!(c.high, 1);
        assert_eq!(c.medium, 2);
        assert_eq!(c.low, 1);
        assert_eq!(c.info, 1);
        assert_eq!(c.total(), 6);
    }

    #[test]
    fn test_severity_counts_top() {
        assert_eq!(SeverityCounts { medium: 11, low: 8, info: 2, ..Default::default() }.top(), "medium");
        assert_eq!(SeverityCounts { low: 3, ..Default::default() }.top(), "low");
        assert_eq!(SeverityCounts::default().top(), "clean");
        assert_eq!(SeverityCounts { critical: 1, high: 5, ..Default::default() }.top(), "critical");
    }

    #[test]
    fn test_truncate_utf8_safe() {
        // Multi-byte Thai must not panic when the cut lands mid-codepoint.
        let thai = "ก".repeat(400); // 3 bytes each = 1200 bytes
        let out = truncate(&thai, 500);
        assert!(out.ends_with('…'));
        assert!(out.len() <= 503);
    }

    #[test]
    fn test_request_accepts_scan_type() {
        let new = json!({"service":"x","scan_id":"1","scan_type":"blackbox","findings":[]});
        let r: HuginnFindingsRequest = serde_json::from_value(new).unwrap();
        assert_eq!(r.scan_type, "blackbox");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_request_accepts_dual_scan_type_keys() {
        // Huginn's REAL payload carries BOTH scan_type and _scan_type. This must
        // not 422 — it would, as a serde "duplicate field", if _scan_type were an
        // alias of scan_type. The legacy key is ignored as unknown.
        let both = json!({
            "service":"mimir-api","scan_id":"1",
            "scan_type":"blackbox","_scan_type":"blackbox",
            "findings":[], "github_issues":[],
            "finding_count":0,
            "severity_counts":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
            "notify_level":"info","status":"completed","target":"http://x"
        });
        let r: HuginnFindingsRequest = serde_json::from_value(both).unwrap();
        assert_eq!(r.scan_type, "blackbox");
        assert_eq!(r.notify_level.as_deref(), Some("info"));
        assert_eq!(r.finding_count, Some(0));
    }
}
