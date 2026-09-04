use anyhow::{Context, Result};
use aqua_matrix_agent::{did_from_key_file, load_dotenv, AgentClient, AgentConfig};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aqua-matrix-agent",
    about = "Matrix agent: authenticate via siwx-oidc, send and read E2EE messages"
)]
struct Args {
    #[arg(long, env = "AGENT_KEY_FILE", default_value = "agent.pem")]
    key_file: PathBuf,

    #[arg(long, env = "SIWX_URL", default_value = "https://siwx-oidc.inblock.io")]
    siwx_url: String,

    #[arg(long, env = "MATRIX_URL", default_value = "https://matrix.inblock.io")]
    matrix_url: String,

    #[arg(
        long,
        env = "OIDC_CLIENT_ID",
        help = "OIDC client ID (auto-registered if omitted)"
    )]
    client_id: Option<String>,

    #[arg(
        long,
        env = "OIDC_REDIRECT_URI",
        help = "OIDC redirect URI (defaults to http://localhost:0/callback)"
    )]
    redirect_uri: Option<String>,

    #[arg(
        long,
        env = "AGENT_TARGET",
        help = "Matrix user ID to message (set AGENT_TARGET, e.g. via a .env file; required for --message/--read)"
    )]
    target: Option<String>,

    #[arg(long, env = "AGENT_STORE_DIR")]
    store_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "AGENT_DEVICE_ID",
        help = "Pin an explicit Matrix device_id (e.g. a role name like 'heartbeat'). Omit to derive a stable id from the agent DID."
    )]
    device_id: Option<String>,

    #[arg(long, help = "Message to send (omit to skip sending)")]
    message: Option<String>,

    #[arg(long, help = "Read recent messages from the DM room")]
    read: bool,

    #[arg(long, default_value = "20")]
    read_limit: u32,

    #[arg(long, help = "Print agent DID and exit")]
    print_did: bool,

    #[arg(
        long,
        env = "AGENT_DISPLAY_NAME",
        help = "Set the Matrix profile display name / alias (idempotent); applied on connect"
    )]
    display_name: Option<String>,

    #[arg(
        long,
        env = "AGENT_AVATAR",
        help = "Set the Matrix profile avatar from an image file (png/jpg/gif/webp); applied on connect (idempotent)"
    )]
    avatar: Option<String>,
}

fn default_store_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".aqua-matrix-agent")
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load instance config from a `.env` file before parsing args, so the
    // env-backed flags below (AGENT_TARGET, MATRIX_URL, …) can be file-driven.
    load_dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,aqua_matrix_agent=info".into()),
        )
        .init();

    let args = Args::parse();

    if args.print_did {
        println!("{}", did_from_key_file(&args.key_file)?);
        return Ok(());
    }

    let config = AgentConfig {
        key_file: args.key_file,
        siwx_url: args.siwx_url,
        matrix_url: args.matrix_url,
        client_id: args.client_id,
        redirect_uri: args.redirect_uri,
        store_dir: args.store_dir.unwrap_or_else(default_store_dir),
        device_id: args.device_id,
    };

    // One-shot CLI: connect once and exit. The long-running daemon modes moved
    // to their own binaries (aqua-matrix-heartbeat, aqua-matrix-claude-p) over
    // the aqua-matrix-relay lifecycle — this binary is now purely the
    // send/read/print-did tool documented in CLAUDE.md.
    let mut agent = AgentClient::connect(config).await?;

    let joined = agent.join_invited_rooms().await?;
    if !joined.is_empty() {
        agent.sync_once().await?;
    }

    // Set the profile display name (alias) when requested. Idempotent: the
    // homeserver PUT is skipped when the name already matches, so wiring this
    // into a per-send .env re-asserts the alias cheaply on every invocation.
    if let Some(ref name) = args.display_name {
        // Best-effort, mirroring the relay: a cosmetic profile write must never
        // block a send (this CLI is the critical-alert notify path).
        match agent.set_display_name(name).await {
            Ok(()) => println!("display name set to {name:?}"),
            Err(e) => eprintln!("warning: failed to set display name {name:?}: {e:#}"),
        }
    }

    if let Some(ref avatar) = args.avatar {
        // Best-effort, mirroring the display-name write above.
        match agent.set_avatar(std::path::Path::new(avatar)).await {
            Ok(()) => println!("avatar set from {avatar:?}"),
            Err(e) => eprintln!("warning: failed to set avatar {avatar:?}: {e:#}"),
        }
    }

    // --message / --read need a target; resolve it once with a clear error if
    // neither --target nor AGENT_TARGET (e.g. from .env) was provided.
    if args.message.is_some() || args.read {
        let target = args
            .target
            .as_deref()
            .context("no target set — pass --target or set AGENT_TARGET (see .env.example)")?;

        if let Some(ref msg) = args.message {
            // Self-healing send: siwx-oidc access tokens live only ~300s and the
            // restored matrix-sdk client can't refresh them itself, so a slow
            // connect() could leave us sending on an expired token (the live
            // M_UNKNOWN_TOKEN failure). send_dm_self_healing proactively rotates
            // a near-expiry token and re-auths-and-retries on a dead one, all
            // non-interactively from the persisted refresh token / the did:key.
            let event_id = agent.send_dm_self_healing(target, msg).await?;
            println!("sent to {target}: {msg} (event: {event_id})");
        }

        if args.read {
            if args.message.is_some() {
                agent.sync_once().await?;
            }
            match agent.dm_room_id(target).await? {
                Some(room_id) => {
                    let messages = agent.messages(&room_id, args.read_limit).await?;
                    if messages.is_empty() {
                        println!("no messages found");
                    } else {
                        for msg in &messages {
                            println!("[{}] {}: {}", msg.timestamp_ms, msg.sender, msg.body);
                        }
                    }
                }
                None => println!("no DM room found with {target}"),
            }
        }
    }

    if args.message.is_none() && !args.read && args.display_name.is_none() && args.avatar.is_none()
    {
        println!("connected as {} ({})", agent.user_id(), agent.did());
        println!("use --message to send or --read to read messages");
    }

    Ok(())
}
