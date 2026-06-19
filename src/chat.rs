use std::convert::Infallible;
use std::sync::Arc;

use async_stream::try_stream;
use axum::{
    extract::{Json, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;

use crate::agents::{AgentConfig, dispatch_tool, http_client, http_client_streaming, tool_definitions};

const MAX_TOOL_ITERATIONS: usize = 6;
const SYSTEM_PROMPT: &str = "You are Odin, the Infrastructure Orchestrator for the Asgard AI Platform.\n\
You monitor, investigate, AND remediate infrastructure, security, and reliability. You have read tools and ACTION tools — you can approve / reject / trigger Muninn fixes, merge PRs, file issues, and run active-response. You are NOT read-only; when asked to act, use the tool.\n\n\
**Available Systems:**\n\
- **Týr** (Wazuh SIEM): security alerts, agent health, rule listing, attack detection\n\
- **Várðr** (Monitoring): service health, metrics, alert management, capacity planning\n\
- **Huginn** (Security Scanner): vulnerability findings, security posture assessment\n\
- **Muninn** (Issue Watcher): issues Muninn actively watches for auto-fix (only the configured repos)\n\
- **Forseti** (E2E Testing): test run results, regression detection, trend analysis\n\
- **Mjölnir** (Load Testing): HTTP load test results, latency, throughput, error rates\n\
- **GitHub**: read issues/PRs on ANY Asgard repo on demand — use `gh_issue_list` (issues) or `gh_pr_list` (PRs) with an 'owner/repo' or a short service name (e.g. 'mimir'). This is NOT limited to the repos Muninn watches, so use it whenever asked to check a specific repo like Mimir.\n\n\
**Knowledge Base (Mimir RAG):**\n\
- Use the **knowledge_search** tool to consult the NCSA *AI Security Guidelines* (แนวปฏิบัติการใช้ปัญญาประดิษฐ์อย่างมั่นคงปลอดภัย) when answering questions about AI/LLM-specific threats (Prompt Injection, Data/Model Poisoning, Model Extraction, AI supply-chain attacks), secure AI lifecycle, AI risk assessment, and recommended security controls. Ground such answers in retrieved passages and cite that the guidance comes from the NCSA AI Security Guidelines.\n\n\
**For Medical/Patient Chat:**\n\
Odin does not handle patient data or medical workflows. Direct users to the **Eir assistant** (integrated inside OpenEMR) for clinical questions, patient chart access, and medical document review.\n\n\
**Knowing yourself — dashboard metrics (this UI computes these; they are NOT version numbers or scan values):**\n\
- **Security Posture** is a 0–100 health score the dashboard computes as: `100 − (failed×10 + review_pending×5 + analyzing×2) − (offline_services×10) − (load_test_failures×10)`, floored at 0. A low number means many open/in-flight issues or offline services — it is NOT itself a vulnerability, and it rises as issues are approved/fixed. It is unrelated to any software version.\n\
- The stat cards (Total Issues, Pending Review, Fixed, Failed, Analyzing, Manual fix, Fixing now, Watchdog) come from Muninn's `/api/progress`; the Policy/Audit feed is the `odin-audit` index (Thor L0–L3 verdicts + Odin governance actions).\n\
- **Muninn issue lifecycle** — when asked about a status, call `muninn_progress` and ground the answer in the real counts; do not answer generically. Statuses: `pending`/`analyzing` = being analyzed; `review_pending` = waiting for a human Approve; `fixing` = a fix is being written; `fixed` = a code PR was opened; `merged` = that PR landed; **`manual_required`** = approved but NO code change was possible — it's an infra/cloud fix (e.g. GCS IAM, DNS) a human applies by hand per the plan; `failed` = the fix errored (the issue's `error` field says why); `skipped` = protected/no-fix. NOT every analyzed issue becomes review_pending — many end at `manual_required` or `merged`.\n\
- **Your action tools** (use them, don't just describe): `muninn_approve_fix` / `muninn_reject_fix` / `muninn_trigger_fix` act on a Muninn issue; `muninn_progress` is the live fix-pipeline state; `merge_pr` merges a fix PR; `create_issue` files one; `active_response` runs a Tyr response. Offer + execute these when a user wants something done.\n\
- **Thor governance tiers** (the Policy/Audit feed): L0 = auto-fix immediately; L1 = AI consensus (Odin + Frigg) on the plan, then auto-fix; **L2 = a human must Approve** before any change; L3 = critical, escalate. WHY a finding got its tier is the audit row's `detail` (e.g. 'security + production repo + medium severity + untrusted source' → L2).\n\
- **Which findings auto-fix vs need a human**: in-repo code problems (missing security headers, CSP, CORS wildcard, dependency CVE bumps) are code-fixable → a PR. Cloud/infra problems (GCS/S3 bucket IAM, public-bucket ACL, DNS, cloud config) have no repo file to change → they end at `manual_required`; tell the user to apply the plan by hand (e.g. a `gcloud` command).\n\
- **Cluster recovery runbook**: if the cluster degrades — pods stuck `Terminating`, `FailedCreatePodSandBox`, or the watchdog reports it unreachable — restart the OrbStack runtime: `orbctl stop` then `orbctl start` (NOT `orb restart`); PVC data survives (incident 2026-06-15-orbstack-runtime-wedge).\n\
- **Watchdog coverage**: asgard-watchdog/preflight checks namespaces `asgard`, `asgard-infra`, `wazuh`. NOT covered (flag these if asked): `asgard-monitoring` (Grafana/Prometheus/Alertmanager — the monitoring stack itself), `asgard-rl` (bifrost-rl), and host services like Heimdall (launchd, not a pod).\n\
- NEVER map a bare dashboard number to an unrelated scan finding just because the digits coincide (e.g. posture 31 is NOT nginx 1.31.x). If you cannot ground a number in an actual tool result, say you are not certain and offer to look it up — do not guess.\n\
- Muninn issues are a FLAT list — there are no epics, parent/child links, or groupings. NEVER claim an issue is an epic, grouped, or related to another unless a tool actually returned that link; `#N` is always one standalone issue.\n\
- A **LIVE SYSTEM STATE** message gives the current counts — answer count/status questions from THOSE numbers and cite your source (e.g. 'per muninn_progress: ...'). If a tool did not return a fact, say you are not certain — never invent a plausible one.\n\n\
- **Never claim, unless a tool result grounds it:** (a) that Muninn will auto-fix / open a PR — true ONLY when `code_agent_provider` is not 'none'; (b) that a 'proposal' is prepared or that someone should 'confirm in the UI' — true ONLY when that issue's status is `review_pending`. When a scan creates no issue, say exactly that — never imply an action that did not happen.\n\n\
**FORMATTING RULES:**\n\
- Use markdown tables for structured data (metrics, alerts, test results).\n\
- Use ```mermaid code blocks for workflow diagrams and relationships.\n\
- Use [document name](url) links when referencing external resources.\n\
- Use **bold** and `code` for emphasis and identifiers.\n\
- Always summarize findings after tool calls — never end with only tool output.\n\
If a tool is unreachable, say the service is unavailable. Never invent data.";

/// Fetch Muninn's current state so the agent answers from real numbers, not from
/// memory — the single biggest lever against hallucinating about our own data.
/// Best-effort: returns None (no injection) only if Muninn's progress is
/// unreachable; stats/issues are folded in opportunistically.
async fn live_grounding(cfg: &AgentConfig) -> Option<Value> {
    let client = crate::agents::http_client();
    // progress is the anchor — if it fails, skip grounding entirely.
    let progress: Value = client
        .get(format!("{}/api/progress", cfg.muninn_url))
        .send().await.ok()?
        .json().await.ok()?;
    // stats (code_agent_provider, total_fixes) + the flat issue list — best-effort.
    let stats: Value = match client.get(format!("{}/api/stats", cfg.muninn_url)).send().await {
        Ok(r) => r.json().await.unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    };
    let issues: Value = match client.get(format!("{}/api/issues", cfg.muninn_url)).send().await {
        Ok(r) => r.json().await.unwrap_or_else(|_| json!([])),
        Err(_) => json!([]),
    };
    Some(json!({ "role": "system", "content": build_grounding_content(&progress, &stats, &issues) }))
}

/// Compose the LIVE SYSTEM STATE block from Muninn's real progress/stats/issues.
/// Pure (no I/O) so it is unit-tested. Beyond the counts, it injects the two facts
/// Odin has been observed to invent: the auto-fix capability flag
/// (`code_agent_provider`) and the COMPLETE flat issue list (so the model cannot
/// fabricate an "Epic #N" or a pending "proposal" that does not exist).
fn build_grounding_content(progress: &Value, stats: &Value, issues: &Value) -> String {
    let counts = progress.get("counts").cloned().unwrap_or(json!({}));
    let paused = progress.get("paused").cloned().unwrap_or(json!(false));
    let watch_org = progress.get("watch_org").and_then(|v| v.as_str()).unwrap_or("");
    let provider = stats.get("code_agent_provider").and_then(|v| v.as_str()).unwrap_or("unknown");
    let total_fixes = stats.get("total_fixes").and_then(|v| v.as_i64()).unwrap_or(-1);
    let watched = stats.get("watched_repos").and_then(|v| v.as_i64()).unwrap_or(-1);

    // Flat one-line inventory `repo#num[status]` — proof there are no epics/children.
    let list = issues.as_array().map(|arr| {
        let mut v: Vec<String> = arr.iter().map(|x| {
            let repo = x.get("repo").and_then(|r| r.as_str()).unwrap_or("?")
                .rsplit('/').next().unwrap_or("?");
            let num = x.get("issue_number").and_then(|n| n.as_i64()).unwrap_or(0);
            let st = x.get("status").and_then(|s| s.as_str()).unwrap_or("?");
            format!("{}#{}[{}]", repo, num, st)
        }).collect();
        v.sort();
        v.join(", ")
    }).unwrap_or_default();

    let autofix = if provider.eq_ignore_ascii_case("none") {
        format!(
            "code_agent_provider=\"{}\" → Muninn CANNOT write auto-fix PRs right now (total_fixes={}). \
             Do NOT claim auto-fix works or that a fix PR is/will be written automatically; \
             code-fixable findings still need a human until a provider is configured.",
            provider, total_fixes
        )
    } else {
        format!("code_agent_provider=\"{}\" (total_fixes={})", provider, total_fixes)
    };

    format!(
        "LIVE SYSTEM STATE — ground every count/status/issue answer in THIS block; do not \
         recall from memory, and if a fact isn't here, call the matching tool instead of guessing.\n\
         • Muninn issue counts: {counts} | paused: {paused} | watch_org: {watch_org} | watched_repos: {watched}\n\
         • {autofix}\n\
         • Open issues are a FLAT list — there are NO epics/parents/children/groupings. The COMPLETE set is exactly: [{list}]. \
         If an issue number is not in this list it does not exist; never invent an 'Epic #N' or claim issues are grouped.\n\
         • There is no separate 'proposal' queue. An item awaits human action ONLY if its status is review_pending. \
         If review_pending is 0/absent, nothing is pending — do NOT tell anyone to 'confirm a proposal in the UI'.",
    )
}

pub async fn run_agent(
    cfg: &Arc<AgentConfig>,
    messages: Vec<Value>,
) -> anyhow::Result<(String, Vec<Value>)> {
    let model = cfg.heimdall_model.clone();
    let mut messages: Vec<Value> = {
        let mut m = vec![json!({"role": "system", "content": SYSTEM_PROMPT})];
        if let Some(ctx) = live_grounding(cfg).await { m.push(ctx); }
        m.extend(messages);
        m
    };
    let tools = tool_definitions();

    for _ in 0..MAX_TOOL_ITERATIONS {
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "stream": false,
            "temperature": 0.3,
            "max_tokens": 4096,
        });

        let client = http_client();
        let mut req_builder = client
            .post(format!("{}/v1/chat/completions", cfg.heimdall_url))
            .header("Content-Type", "application/json");
        if let Some(k) = &cfg.heimdall_api_key {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", k));
        }
        let resp = req_builder.json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Heimdall {}: {}", status, txt));
        }

        let resp_json: Value = resp.json().await?;
        let choice = resp_json
            .get("choices")
            .and_then(|c| c.get(0))
            .ok_or_else(|| anyhow::anyhow!("no choice in response"))?;

        let assistant_text = choice
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let tool_calls = choice
            .get("message")
            .and_then(|m| m.get("tool_calls"))
            .and_then(|tc| tc.as_array())
            .cloned()
            .unwrap_or_default();

        let finish_reason = choice
            .get("finish_reason")
            .and_then(|fr| fr.as_str())
            .unwrap_or("");

        // Run tools whenever the model emitted any. Providers disagree on
        // finish_reason: Claude → "tool_calls", Gemini (via Heimdall) → "stop"
        // even with tool calls present, so we key off tool_calls, not the reason.
        let _ = finish_reason;
        if tool_calls.is_empty() {
            return Ok((assistant_text, messages));
        }

        let assistant_msg = json!({
            "role": "assistant",
            "content": if assistant_text.is_empty() { Value::Null } else { Value::String(assistant_text) },
            "tool_calls": tool_calls,
        });
        messages.push(assistant_msg);

        for call in tool_calls.iter() {
            let id = call.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let name = call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let args_str = call
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap_or("{}");

            let args: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
            let result = match dispatch_tool(cfg, name, &args).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("tool {} failed: {}", name, e);
                    json!({ "error": e.to_string() })
                }
            };

            messages.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": result.to_string(),
            }));
        }
    }

    Err(anyhow::anyhow!("max tool iterations reached"))
}

#[derive(Clone)]
pub struct ChatState {
    pub cfg: Arc<AgentConfig>,
}

#[derive(Deserialize)]
pub struct ChatRequest {
    pub messages: Vec<Value>,
}

pub async fn chat_handler(
    State(state): State<ChatState>,
    Json(req): Json<ChatRequest>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let cfg = state.cfg.clone();
    let model = cfg.heimdall_model.clone();

    let stream = try_stream! {
        let mut messages: Vec<Value> = vec![json!({"role": "system", "content": SYSTEM_PROMPT})];
        if let Some(ctx) = live_grounding(&cfg).await { messages.push(ctx); }
        messages.extend(req.messages.into_iter());
        let tools = tool_definitions();

        for iter in 0..MAX_TOOL_ITERATIONS {
            let body = json!({
                "model": model,
                "messages": messages,
                "tools": tools,
                "stream": true,
                "temperature": 0.3,
                "max_tokens": 4096,
            });

            let client = http_client_streaming();
            let mut req_builder = client
                .post(format!("{}/v1/chat/completions", cfg.heimdall_url))
                .header("Content-Type", "application/json");
            if let Some(k) = &cfg.heimdall_api_key {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", k));
            }
            let resp = match req_builder.json(&body).send().await {
                Ok(r) => r,
                Err(e) => {
                    let mut detail = format!("{}", e);
                    let mut src = std::error::Error::source(&e);
                    while let Some(s) = src {
                        detail.push_str(&format!(" → {}", s));
                        src = s.source();
                    }
                    let kind = if e.is_timeout() { "timeout" }
                        else if e.is_connect() { "connect" }
                        else if e.is_request() { "request" }
                        else { "unknown" };
                    yield sse_error(format!("Heimdall [{}]: {}", kind, detail));
                    return;
                }
            };
            if !resp.status().is_success() {
                let status = resp.status();
                let txt = resp.text().await.unwrap_or_default();
                yield sse_error(format!("Heimdall {}: {}", status, txt));
                return;
            }

            let mut byte_stream = resp.bytes_stream();
            let mut buf = String::new();
            let mut assistant_text = String::new();
            // tool_calls accumulated by index across deltas:
            // (id, name, args_json_string, extra_content). extra_content carries
            // provider-specific data (e.g. Gemini's thought_signature) that MUST
            // be replayed on the assistant message or Gemini rejects the follow-up.
            let mut tool_calls: Vec<(String, String, String, Option<Value>)> = Vec::new();
            let mut finish_reason = String::new();

            while let Some(chunk) = byte_stream.next().await {
                let bytes = match chunk {
                    Ok(b) => b,
                    Err(e) => {
                        yield sse_error(format!("stream error: {}", e));
                        return;
                    }
                };
                buf.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(pos) = buf.find("\n\n") {
                    let event = buf[..pos].to_string();
                    buf = buf[pos + 2..].to_string();
                    for line in event.lines() {
                        let line = line.trim_start();
                        if !line.starts_with("data:") { continue; }
                        let payload = line[5..].trim();
                        if payload == "[DONE]" { continue; }
                        let v: Value = match serde_json::from_str(payload) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let choice = v.get("choices").and_then(|c| c.get(0));
                        if let Some(choice) = choice {
                            if let Some(delta) = choice.get("delta") {
                                if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                                    if !content.is_empty() {
                                        assistant_text.push_str(content);
                                        yield sse_json(&json!({"type":"delta","content":content}));
                                    }
                                }
                                if let Some(tc) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                                    for call in tc {
                                        // Resolve which accumulator slot this delta belongs to.
                                        // OpenAI/Claude split a single call's args across deltas keyed
                                        // by a per-call `index`. Gemini-via-Heimdall omits that index
                                        // and instead emits each PARALLEL call complete in its own
                                        // delta with a fresh `id`. Defaulting a missing index to 0
                                        // collapses every parallel call into slot 0 — the args then
                                        // concatenate (e.g. "{}{}{}"), which is invalid JSON and makes
                                        // Gemini reject the follow-up with 400 INVALID_ARGUMENT. So:
                                        // index if present, else match/append by id, else continue last.
                                        let id_opt = call.get("id").and_then(|s| s.as_str()).filter(|s| !s.is_empty());
                                        let idx = if let Some(i) = call.get("index").and_then(|i| i.as_u64()) {
                                            let i = i as usize;
                                            while tool_calls.len() <= i {
                                                tool_calls.push((String::new(), String::new(), String::new(), None));
                                            }
                                            i
                                        } else if let Some(id) = id_opt {
                                            match tool_calls.iter().position(|e| e.0 == id) {
                                                Some(p) => p,
                                                None => {
                                                    tool_calls.push((id.to_string(), String::new(), String::new(), None));
                                                    tool_calls.len() - 1
                                                }
                                            }
                                        } else {
                                            if tool_calls.is_empty() {
                                                tool_calls.push((String::new(), String::new(), String::new(), None));
                                            }
                                            tool_calls.len() - 1
                                        };
                                        let entry = &mut tool_calls[idx];
                                        if let Some(id) = id_opt {
                                            if entry.0.is_empty() { entry.0 = id.to_string(); }
                                        }
                                        if let Some(ec) = call.get("extra_content") {
                                            if !ec.is_null() { entry.3 = Some(ec.clone()); }
                                        }
                                        if let Some(func) = call.get("function") {
                                            if let Some(n) = func.get("name").and_then(|s| s.as_str()) {
                                                if !n.is_empty() { entry.1 = n.to_string(); }
                                            }
                                            if let Some(a) = func.get("arguments").and_then(|s| s.as_str()) {
                                                entry.2.push_str(a);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(fr) = choice.get("finish_reason").and_then(|s| s.as_str()) {
                                if !fr.is_empty() { finish_reason = fr.to_string(); }
                            }
                        }
                    }
                }
            }

            // Run tools whenever the model emitted any. Providers disagree on
            // finish_reason: Claude → "tool_calls", Gemini (via Heimdall) → "stop"
            // even with tool calls present, so key off the accumulated calls.
            let _ = &finish_reason;
            let has_tool_calls = tool_calls.iter().any(|(_, name, _, _)| !name.is_empty());
            if !has_tool_calls {
                yield sse_json(&json!({"type":"done"}));
                return;
            }

            // Build the assistant message that requested tools, append, then run each tool
            let assistant_msg = json!({
                "role": "assistant",
                "content": if assistant_text.is_empty() { Value::Null } else { Value::String(assistant_text.clone()) },
                "tool_calls": tool_calls.iter().map(|(id, name, args, extra)| {
                    let mut tc = json!({
                        "id": id,
                        "type": "function",
                        "function": { "name": name, "arguments": args }
                    });
                    // Replay provider extras (Gemini thought_signature) on the
                    // assistant message, or the follow-up request is rejected.
                    if let Some(ec) = extra {
                        tc["extra_content"] = ec.clone();
                    }
                    tc
                }).collect::<Vec<_>>(),
            });
            messages.push(assistant_msg);

            for (id, name, args_str, _) in tool_calls.iter() {
                let args: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
                yield sse_json(&json!({"type":"tool_call","name":name,"args":args}));
                let result = match dispatch_tool(&cfg, name, &args).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("tool {} failed: {}", name, e);
                        json!({ "error": e.to_string() })
                    }
                };
                yield sse_json(&json!({"type":"tool_result","name":name,"result":result}));
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": id,
                    "content": result.to_string(),
                }));
            }

            if iter == MAX_TOOL_ITERATIONS - 1 {
                yield sse_error("max tool iterations reached".into());
                return;
            }
        }
    };

    let event_stream = stream.map(|r: Result<Event, Infallible>| r);
    Sse::new(event_stream).keep_alive(KeepAlive::default())
}

fn sse_json(v: &Value) -> Event {
    Event::default().data(v.to_string())
}

fn sse_error(msg: String) -> Event {
    Event::default().data(json!({ "type": "error", "message": msg }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grounding_flags_no_autofix_and_lists_issues_flat() {
        let progress = json!({
            "counts": {"manual_required": 12, "merged": 1, "analyzing": 2},
            "paused": false, "watch_org": "MegaWiz-Dev-Team"
        });
        let stats = json!({"code_agent_provider": "none", "total_fixes": 0, "watched_repos": 5});
        let issues = json!([
            {"repo": "MegaWiz-Dev-Team/Asgard", "issue_number": 99, "status": "manual_required"},
            {"repo": "MegaWiz-Dev-Team/Bifrost", "issue_number": 22, "status": "manual_required"}
        ]);
        let s = build_grounding_content(&progress, &stats, &issues);
        // (a) auto-fix is off → must say so, blocking the "Muninn will write a PR" claim
        assert!(s.contains("CANNOT"), "must warn auto-fix unavailable when provider=none: {s}");
        // (b) the flat issue list is injected verbatim → blocks invented "Epic #N"
        assert!(s.contains("Asgard#99[manual_required]"), "issue list missing: {s}");
        assert!(s.contains("Bifrost#22[manual_required]"));
        assert!(s.contains("FLAT list"));
        // (c) proposal/confirm semantics tied to review_pending → blocks the Discord over-claim
        assert!(s.contains("review_pending"), "must explain proposal/confirm semantics: {s}");
    }

    #[test]
    fn grounding_reports_provider_when_configured() {
        let progress = json!({"counts": {}, "paused": false, "watch_org": "x"});
        let stats = json!({"code_agent_provider": "claude-code", "total_fixes": 3, "watched_repos": 5});
        let s = build_grounding_content(&progress, &stats, &json!([]));
        assert!(!s.contains("CANNOT"), "configured provider must NOT trigger the can't-autofix warning: {s}");
        assert!(s.contains("claude-code"));
    }
}
