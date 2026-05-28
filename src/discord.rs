use std::collections::HashMap;
use std::sync::Arc;

use serenity::all::{Context, EventHandler, Message};
use serenity::async_trait;
use serenity::Client;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::agents::AgentConfig;
use crate::chat::run_agent;

pub struct Handler {
    cfg: Arc<AgentConfig>,
    history: Arc<tokio::sync::Mutex<HashMap<u64, Vec<Value>>>>,
}

impl Handler {
    fn new(cfg: Arc<AgentConfig>) -> Self {
        Self {
            cfg,
            history: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.bot {
            return;
        }

        let channel_id = msg.channel_id.get();
        let configured_channel = self.cfg.discord_channel_id.parse::<u64>().ok();

        let should_respond = if let Some(configured) = configured_channel {
            channel_id == configured || msg.mentions.iter().any(|u| u.id == ctx.cache.current_user().id)
        } else {
            msg.mentions.iter().any(|u| u.id == ctx.cache.current_user().id)
        };

        if !should_respond {
            return;
        }

        let _ = msg.channel_id.broadcast_typing(&ctx).await;

        let mut history = self.history.lock().await;
        let channel_history = history.entry(channel_id).or_insert_with(Vec::new);

        channel_history.push(json!({
            "role": "user",
            "content": msg.content_safe(&ctx)
        }));

        let history_to_use = channel_history.clone();
        drop(history);

        match run_agent(&self.cfg, history_to_use).await {
            Ok((response_text, updated_messages)) => {
                let mut history = self.history.lock().await;
                let channel_history = history.entry(channel_id).or_insert_with(Vec::new);
                *channel_history = updated_messages;

                const DISCORD_MSG_LIMIT: usize = 2000;
                if response_text.len() <= DISCORD_MSG_LIMIT {
                    if let Err(e) = msg.reply(&ctx, &response_text).await {
                        warn!("failed to send Discord reply: {}", e);
                    }
                } else {
                    for chunk in response_text.chars().collect::<Vec<_>>().chunks(DISCORD_MSG_LIMIT) {
                        let chunk_str: String = chunk.iter().collect();
                        if let Err(e) = msg.reply(&ctx, &chunk_str).await {
                            warn!("failed to send Discord chunk: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("agent error: {}", e);
                if let Err(e) = msg.reply(&ctx, &format!("❌ Agent error: {}", e)).await {
                    warn!("failed to send error reply: {}", e);
                }
            }
        }
    }

    async fn ready(&self, _ctx: Context, ready: serenity::model::gateway::Ready) {
        info!("Discord bot ready as {}", ready.user.name);
    }
}

pub async fn start_bot(cfg: Arc<AgentConfig>) {
    let Some(token) = cfg.discord_token.clone() else {
        info!("DISCORD_TOKEN not set — bot disabled");
        return;
    };

    let intents = serenity::all::GatewayIntents::GUILD_MESSAGES
        | serenity::all::GatewayIntents::MESSAGE_CONTENT
        | serenity::all::GatewayIntents::DIRECT_MESSAGES;

    let mut client = match Client::builder(&token, intents)
        .event_handler(Handler::new(cfg))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to create Discord client: {}", e);
            return;
        }
    };

    if let Err(e) = client.start().await {
        warn!("Discord client error: {}", e);
    }
}
