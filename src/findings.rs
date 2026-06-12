use axum::{extract::{Json, State, Path}, http::StatusCode, response::Html};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;
use once_cell::sync::Lazy;
use std::collections::HashMap;

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
