//! Channel Bridge Layer for the OpenFang Agent OS.
//!
//! Provides 40 pluggable messaging integrations that convert platform messages
//! into unified `ChannelMessage` events for the kernel.

pub mod bridge;
pub mod discord;
pub mod email;
pub mod formatter;
pub mod google_chat;
pub mod irc;
pub mod matrix;
pub mod mattermost;
pub mod rocketchat;
pub mod router;
pub mod signal;
pub mod slack;
pub mod teams;
pub mod telegram;
pub mod twitch;
pub mod types;
pub mod whatsapp;
pub mod xmpp;
pub mod zulip;
// Wave 3 — High-value channels
pub mod bluesky;
pub mod feishu;
pub mod line;
pub mod mastodon;
pub mod messenger;
pub mod reddit;
pub mod revolt;
pub mod viber;
// Wave 4 — Enterprise & community channels
pub mod flock;
pub mod guilded;
pub mod keybase;
pub mod nextcloud;
pub mod nostr;
pub mod pumble;
pub mod threema;
pub mod twist;
pub mod webex;
// Wave 5 — Niche & differentiating channels
pub mod dingtalk;
pub mod dingtalk_stream;
pub mod discourse;
pub mod gitter;
pub mod gotify;
pub mod linkedin;
pub mod mumble;
pub mod mqtt;
pub mod ntfy;
pub mod webhook;
pub mod wecom;

/// Build a channel HTTP client with redirects disabled.
///
/// SECURITY: Prevents SSRF via redirect — if an admin-configured webhook URL
/// returns a 302 to an internal host (e.g., cloud IMDS), the redirect is not
/// followed. All channel adapters should use this instead of `reqwest::Client::new()`.
pub fn channel_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build channel HTTP client")
}
