use anyhow::Result;
use serde_json::json;

pub async fn send_discord_webhook(webhook_url: &str, message: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let payload = json!({
        "content": message
    });

    client.post(webhook_url)
        .json(&payload)
        .send()
        .await?;

    Ok(())
}