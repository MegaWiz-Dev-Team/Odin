mod agents;
mod chat;
mod discord;
mod findings;
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
    }))
}

/// Proxy Muninn's tracked issues through Odin (browser can't reach Muninn's
/// ClusterIP / localhost-only port-forward, esp. over Tailscale). Returns the
/// raw JSON array, or [] on any failure so the UI degrades gracefully.
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
        .route("/api/config", axum::routing::get(config_proxy))
        .layer(middleware::from_fn(require_auth));

    // Public — login (issues the token), the Huginn webhook (machine-to-machine),
    // report HTML links, and the static dashboard UI.
    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/huginn-findings", post(findings::huginn_findings_handler))
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
