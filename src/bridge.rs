//! Týr alert → GitHub issue auto-bridge.
//!
//! Closes the "autonomous" gap left in Phase 2: instead of a human asking Odin
//! in chat to file an issue, this background loop polls the Týr (Wazuh) indexer
//! for high-severity alerts and files a GitHub issue for each *new* alert type,
//! reusing the same dedup + create path as the HITL endpoint.
//!
//! Safety gates (all conservative by default):
//!   - **Default OFF** — only runs when `TYR_AUTO_BRIDGE=true`.
//!   - **Severity threshold** — `TYR_BRIDGE_MIN_LEVEL` (default 12 = critical).
//!   - **Dedup** — `repo+title` fingerprint; recurring identical alerts skip.
//!   - **Rate cap** — `TYR_BRIDGE_MAX_PER_CYCLE` (default 5) per poll.
//!   - **Audit** — every filed issue logged to the `odin-audit` index.
//!   - **No-op without token** — skips cleanly until `GITHUB_TOKEN` is wired.
//! Issues stay T2 (staged): the downstream Muninn PR is still draft + HITL.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::agents::{self, AgentConfig};

fn env_num(key: &str, default: i64) -> i64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Background loop. Spawned from `main`. Returns immediately (logging) if disabled.
pub async fn start_alert_bridge(cfg: Arc<AgentConfig>) {
    let enabled = std::env::var("TYR_AUTO_BRIDGE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if !enabled {
        info!("🌉 Týr alert→issue bridge: DISABLED (set TYR_AUTO_BRIDGE=true to enable)");
        return;
    }

    let min_level = env_num("TYR_BRIDGE_MIN_LEVEL", 12);
    let interval = env_num("TYR_BRIDGE_INTERVAL_SECS", 120).max(15) as u64;
    let max_per_cycle = env_num("TYR_BRIDGE_MAX_PER_CYCLE", 5).max(1) as usize;
    info!(
        "🌉 Týr alert→issue bridge: ENABLED (rule.level>={}, every {}s, max {}/cycle)",
        min_level, interval, max_per_cycle
    );

    let client = agents::http_client();
    loop {
        if cfg.github_token.is_none() {
            warn!("🌉 bridge: GITHUB_TOKEN not set on Odin — skipping cycle");
        } else if let Err(e) = run_cycle(&client, &cfg, min_level, max_per_cycle).await {
            warn!("🌉 bridge cycle error: {}", e);
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

async fn run_cycle(
    client: &Client,
    cfg: &AgentConfig,
    min_level: i64,
    max_per_cycle: usize,
) -> anyhow::Result<()> {
    let query = format!("rule.level:>={}", min_level);
    let result = agents::tyr_search_alerts(client, cfg, &query, 30).await?;
    let alerts = result
        .get("alerts")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    if alerts.is_empty() {
        return Ok(());
    }

    let mut created = 0usize;
    for a in &alerts {
        if created >= max_per_cycle {
            info!("🌉 hit cap {}/cycle — remaining alerts deferred to next cycle", max_per_cycle);
            break;
        }

        let level = a.pointer("/rule/level").and_then(value_i64).unwrap_or(0);
        if level < min_level {
            continue;
        }
        let desc = a
            .pointer("/rule/description")
            .and_then(|v| v.as_str())
            .unwrap_or("(no description)");
        let agent = a
            .pointer("/agent/name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let rule_id = a
            .pointer("/rule/id")
            .map(stringify_scalar)
            .unwrap_or_else(|| "?".into());
        let ts = a.get("@timestamp").and_then(|v| v.as_str()).unwrap_or("");

        let repo = agents::service_to_repo(agent);
        // Title is stable per alert *type* (no timestamp) → recurring alerts dedup.
        let title = format!("[Týr] {} (level {}) on {}", desc, level, agent);
        let body = format!(
            "## 🛡️ Týr SIEM alert (auto-filed by Odin)\n\n\
             - **Rule:** {} (id `{}`)\n\
             - **Level:** {}\n\
             - **Agent:** `{}`\n\
             - **First seen:** {}\n\n\
             Filed automatically by the Odin Týr alert→issue bridge. Recurring identical \
             alerts are deduplicated (same `repo+title` fingerprint). Triage and, if this is \
             a code-level issue, keep the `security` label so Muninn can propose a draft fix.\n\n\
             _Add label `muninn-skip` to opt this issue out of auto-fix._",
            desc, rule_id, level, agent, ts
        );
        let labels = ["odin", "tyr-alert", "security"];

        let outcome = agents::create_issue_core(client, cfg, &repo, &title, &body, &labels).await;
        match outcome.status {
            "created" => {
                created += 1;
                let url = outcome.issue_url.clone().unwrap_or_default();
                info!("🌉 filed {} → {}", repo, url);
                audit(client, cfg, &repo, &title, &outcome, &rule_id, level, ts).await;
            }
            "duplicate" => { /* already filed — stay quiet to avoid log spam */ }
            _ => warn!(
                "🌉 failed to file {}: {}",
                repo,
                outcome.error.as_deref().unwrap_or("unknown")
            ),
        }
    }

    if created > 0 {
        info!("🌉 bridge cycle complete: {} new issue(s) filed", created);
    }
    Ok(())
}

/// Append an audit record for a filed issue to the `odin-audit` index.
async fn audit(
    client: &Client,
    cfg: &AgentConfig,
    repo: &str,
    title: &str,
    outcome: &agents::IssueOutcome,
    rule_id: &str,
    level: i64,
    ts: &str,
) {
    let url = format!("{}/odin-audit/_doc", cfg.tyr_indexer_url);
    let body = json!({
        "action": "tyr_bridge_create_issue",
        "actor": "odin-tyr-bridge",
        "repo": repo,
        "title": title,
        "issue_url": outcome.issue_url,
        "fingerprint": outcome.fingerprint,
        "rule_id": rule_id,
        "level": level,
        "alert_ts": ts,
    });
    let _ = client
        .post(&url)
        .basic_auth(cfg.tyr_indexer_user.clone(), Some(cfg.tyr_indexer_pass.clone()))
        .json(&body)
        .send()
        .await;
}

/// `rule.level` may arrive as a JSON number or a stringified number ("12").
fn value_i64(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Render a scalar JSON value (string or number) as a plain string.
fn stringify_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
