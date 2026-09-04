//! Diagnostic: does a freshly-connected identity see a pending invite via the
//! classic `sync_once` path (the one `tests/e2e.rs` uses successfully)?
//!
//!   cargo run -p aqua-matrix-agent --example invite_probe -- \
//!     --key-file /tmp/chan11.pem --store-dir ~/.aqua-chan11

use std::path::PathBuf;

use aqua_matrix_agent::{AgentClient, AgentConfig};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long)]
    store_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,aqua_matrix_agent=info".into()),
        )
        .try_init()
        .ok();
    let args = Args::parse();
    let agent = AgentClient::connect(AgentConfig {
        key_file: args.key_file,
        siwx_url: "https://siwx-oidc.inblock.io".into(),
        matrix_url: "https://matrix.inblock.io".into(),
        client_id: None,
        redirect_uri: None,
        store_dir: args.store_dir,
        // None → connect() derives a stable device_id from the DID.
        device_id: None,
    })
    .await
    .expect("connect failed");
    println!("connected as {}", agent.user_id());

    for i in 0..6 {
        agent.sync_once().await.expect("sync failed");
        let n = agent.client().invited_rooms().len();
        let joined = agent.client().joined_rooms().len();
        println!("sync #{i}: invited_rooms={n} joined_rooms={joined}");
    }

    println!("invited rooms detail:");
    for r in agent.client().invited_rooms() {
        println!("  invite: {} (name={:?})", r.room_id(), r.name());
    }
    match agent.join_invited_rooms().await {
        Ok(j) => println!("join_invited_rooms -> {:?}", j),
        Err(e) => println!("join_invited_rooms ERR: {e:#}"),
    }
}
