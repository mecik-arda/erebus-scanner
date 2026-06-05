use anyhow::Result;
use serde_json::json;

pub async fn send_discord_webhook(webhook_url: &str, message: &str) -> Result<()> {
    // SSRF protection: only allow HTTPS URLs to known webhook services
    if !webhook_url.starts_with("https://discord.com/api/webhooks/")
        && !webhook_url.starts_with("https://discordapp.com/api/webhooks/")
        && !webhook_url.starts_with("https://hooks.slack.com/")
    {
        return Err(anyhow::anyhow!(
            "Invalid webhook URL. Only Discord and Slack HTTPS webhook URLs are allowed."
        ));
    }

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