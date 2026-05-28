mod agents;
mod chat;
mod discord;
mod findings;
mod report;

use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
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

    if user == "admin" && pass == "admin" {
        let response = LoginResponse {
            token: "odin-secret-bearer-token".to_string(),
        };
        (StatusCode::OK, Json(response)).into_response()
    } else {
        let response = ErrorResponse {
            error: "Invalid username or password".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(response)).into_response()
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

    // Build our application with routes
    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/chat", post(chat::chat_handler))
        .route("/api/huginn-findings", post(findings::huginn_findings_handler))
        .route("/api/reports/{scan_id}", axum::routing::get(findings::get_report_html))
        .with_state(chat_state)
        .fallback_service(static_dir)
        .layer(TraceLayer::new_for_http());

    // Spawn Discord bot in background if token is configured
    let discord_cfg = cfg.clone();
    tokio::spawn(async move {
        discord::start_bot(discord_cfg).await;
    });

    // Run our app
    let port = 3000;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("🏛️ Odin API Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
