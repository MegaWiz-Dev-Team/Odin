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

use crate::agents::{AgentConfig, dispatch_tool, http_client_streaming, tool_definitions};

const MAX_TOOL_ITERATIONS: usize = 6;
const SYSTEM_PROMPT: &str = "You are Odin, the Infrastructure Orchestrator for the Asgard AI Platform.\n\
You monitor and investigate infrastructure, security, and reliability via read-only tools.\n\n\
**Available Systems:**\n\
- **Týr** (Wazuh SIEM): security alerts, agent health, rule listing, attack detection\n\
- **Várðr** (Monitoring): service health, metrics, alert management, capacity planning\n\
- **Huginn** (Security Scanner): vulnerability findings, security posture assessment\n\
- **Muninn** (Issue Watcher): tracked issues, remediation suggestions\n\
- **Forseti** (E2E Testing): test run results, regression detection, trend analysis\n\
- **Mjölnir** (Load Testing): HTTP load test results, latency, throughput, error rates\n\n\
**For Medical/Patient Chat:**\n\
Odin does not handle patient data or medical workflows. Direct users to the **Eir assistant** (integrated inside OpenEMR) for clinical questions, patient chart access, and medical document review.\n\n\
**FORMATTING RULES:**\n\
- Use markdown tables for structured data (metrics, alerts, test results).\n\
- Use ```mermaid code blocks for workflow diagrams and relationships.\n\
- Use [document name](url) links when referencing external resources.\n\
- Use **bold** and `code` for emphasis and identifiers.\n\
- Always summarize findings after tool calls — never end with only tool output.\n\
If a tool is unreachable, say the service is unavailable. Never invent data.";

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
        messages.extend(req.messages.into_iter());
        let tools = tool_definitions();

        for iter in 0..MAX_TOOL_ITERATIONS {
            let body = json!({
                "model": model,
                "messages": messages,
                "tools": tools,
                "stream": true,
                "temperature": 0.3,
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
            // tool_calls accumulated by index across deltas: (id, name, args_json_string)
            let mut tool_calls: Vec<(String, String, String)> = Vec::new();
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
                                        let idx = call.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                                        while tool_calls.len() <= idx {
                                            tool_calls.push((String::new(), String::new(), String::new()));
                                        }
                                        let entry = &mut tool_calls[idx];
                                        if let Some(id) = call.get("id").and_then(|s| s.as_str()) {
                                            if !id.is_empty() { entry.0 = id.to_string(); }
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

            if tool_calls.is_empty() || finish_reason != "tool_calls" {
                yield sse_json(&json!({"type":"done"}));
                return;
            }

            // Build the assistant message that requested tools, append, then run each tool
            let assistant_msg = json!({
                "role": "assistant",
                "content": if assistant_text.is_empty() { Value::Null } else { Value::String(assistant_text.clone()) },
                "tool_calls": tool_calls.iter().map(|(id, name, args)| json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": args }
                })).collect::<Vec<_>>(),
            });
            messages.push(assistant_msg);

            for (id, name, args_str) in tool_calls.iter() {
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
