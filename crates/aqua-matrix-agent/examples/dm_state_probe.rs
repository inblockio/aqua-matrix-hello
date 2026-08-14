//! One-shot DM-state probe, written for the agent-initiated-hello e2e
//! verification: connect as a (test) peer identity, join any pending invite,
//! and print — for the DM with `AGENT_TARGET` — the room id, the room's
//! E2E-encryption state, the number of `m.direct` entries, and the last few
//! messages. This asserts, from the peer's own session, that an agent-created
//! DM room is encrypted, its greeting decrypts, and no duplicate room exists —
//! without extracting any access token.
//!
//! Env (mirrors the one-shot CLI): `AGENT_KEY_FILE`, `AGENT_STORE_DIR`,
//! `AGENT_TARGET` (required); `SIWX_URL` / `MATRIX_URL` / `OIDC_CLIENT_ID` /
//! `OIDC_REDIRECT_URI` / `AGENT_DEVICE_ID` optional.
//!
//! Run: `cargo run --example dm_state_probe`

use anyhow::{Context, Result};
use aqua_matrix_agent::{AgentClient, AgentConfig};
use matrix_sdk::ruma::events::direct::{DirectEventContent, OwnedDirectUserIdentifier};
use matrix_sdk::ruma::{OwnedRoomId, OwnedUserId};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn,aqua_matrix_agent=info")
        .init();

    let env = |k: &str| std::env::var(k).ok();
    let target = env("AGENT_TARGET").context("set AGENT_TARGET to the agent's MXID")?;
    let config = AgentConfig {
        key_file: env("AGENT_KEY_FILE")
            .context("set AGENT_KEY_FILE")?
            .into(),
        siwx_url: env("SIWX_URL").unwrap_or_else(|| "https://siwx-oidc.inblock.io".into()),
        matrix_url: env("MATRIX_URL").unwrap_or_else(|| "https://matrix.inblock.io".into()),
        client_id: env("OIDC_CLIENT_ID"),
        redirect_uri: env("OIDC_REDIRECT_URI"),
        store_dir: env("AGENT_STORE_DIR")
            .context("set AGENT_STORE_DIR")?
            .into(),
        device_id: env("AGENT_DEVICE_ID"),
    };

    let agent = AgentClient::connect(config).await?;
    // Sync first so a just-sent invite is visible, then join it (same order as
    // the relay daemon), then settle.
    agent.sync_once().await?;
    for room_id in &agent.join_invited_rooms().await? {
        println!("joined-invite: {room_id}");
    }
    agent.sync_once().await?;

    // m.direct entries for the target (duplicate-room detector).
    let uid: OwnedUserId = target.as_str().try_into().context("invalid AGENT_TARGET")?;
    let key: OwnedDirectUserIdentifier = uid.into();
    let entries = agent
        .client()
        .account()
        .fetch_account_data_static::<DirectEventContent>()
        .await?
        .map(|raw| raw.deserialize())
        .transpose()?
        .and_then(|content| content.get(&key).map(|rooms| rooms.len()))
        .unwrap_or(0);
    println!("m.direct-entries[{target}]: {entries}");

    match agent.dm_room_id(&target).await? {
        None => println!("dm-room: NONE"),
        Some(room_id) => {
            println!("dm-room: {room_id}");
            let rid: OwnedRoomId = room_id.as_str().try_into()?;
            let room = agent
                .client()
                .get_room(&rid)
                .context("DM room not in store after sync")?;
            let encrypted = room.latest_encryption_state().await?.is_encrypted();
            println!("room-encrypted: {encrypted}");
            for m in agent.messages(&room_id, 10).await? {
                println!("[{}] {}: {}", m.timestamp_ms, m.sender, m.body);
            }
        }
    }
    Ok(())
}
