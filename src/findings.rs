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
