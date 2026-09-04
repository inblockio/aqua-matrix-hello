//! Persistent e2e driver for the chat-confirmations Phase A/B walkthrough.
//!
//! Plays the *human* side of the conversation: it connects as a normal agent
//! identity, holds the DM room open across the whole session (unlike the
//! one-shot `aqua-matrix-agent --message` CLI, which cold-syncs per call and
//! races room/membership convergence), scripts the four tests against a live
//! `aqua-matrix-claude-p` daemon, and prints a transcript plus verdicts.
//!
//! It controls only side A. Side B is the real daemon (separate process), which
//! joins the invite and replies on its own — so this exercises the genuine
//! Matrix + `claude -p` transport end to end.
//!
//! Run:
//!   cargo run -p aqua-matrix-agent --example chat_e2e_driver -- \
//!     --key-file /tmp/drv.pem --store-dir ~/.aqua-drv \
//!     --target <channel-matrix-user-id> \
//!     --approve-canary /tmp/e2e-approve.txt \
//!     --deny-canary /tmp/e2e-deny.txt

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aqua_matrix_agent::{AgentClient, AgentConfig, Message};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long, default_value = "https://siwx-oidc.inblock.io")]
    siwx_url: String,
    #[arg(long, default_value = "https://matrix.inblock.io")]
    matrix_url: String,
    #[arg(long)]
    store_dir: PathBuf,
    /// Matrix user id of the claude-channel daemon under test.
    #[arg(long)]
    target: String,
    #[arg(long)]
    approve_canary: String,
    #[arg(long)]
    deny_canary: String,
}

const POLL: Duration = Duration::from_secs(3);

fn exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// Sync once, fetch recent messages, return the *new* ones from `channel`
/// (event ids not seen before). Every observed event id is recorded so a
/// message is reported exactly once.
async fn drain_new(
    agent: &AgentClient,
    room_id: &str,
    seen: &mut HashSet<String>,
    channel: &str,
) -> Vec<Message> {
    if let Err(e) = agent.sync_once().await {
        eprintln!("[driver] sync error: {e:#}");
    }
    let msgs = match agent.messages(room_id, 40).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[driver] messages error: {e:#}");
            return Vec::new();
        }
    };
    let mut fresh = Vec::new();
    for m in msgs {
        // Synapse canonicalises (lowercases) Matrix user IDs, so the daemon's
        // sender comes back lowercased while `channel` is the mixed-case
        // DID-derived id — compare case-insensitively.
        if seen.insert(m.event_id.clone()) && m.sender.eq_ignore_ascii_case(channel) {
            fresh.push(m);
        }
    }
    fresh
}

/// Poll until a new channel message satisfies `pred`, or `timeout` elapses.
/// Prints every channel line as it arrives. Returns all collected channel
/// messages and whether the predicate fired.
async fn wait_for<F: Fn(&str) -> bool>(
    agent: &AgentClient,
    room_id: &str,
    seen: &mut HashSet<String>,
    channel: &str,
    label: &str,
    pred: F,
    timeout: Duration,
) -> (Vec<Message>, bool) {
    let deadline = Instant::now() + timeout;
    let mut collected = Vec::new();
    loop {
        for m in drain_new(agent, room_id, seen, channel).await {
            let body = m.body.replace('\n', "\n        ");
            println!("    <<CHANNEL [{label}]>> {body}");
            let hit = pred(&m.body);
            collected.push(m);
            if hit {
                return (collected, true);
            }
        }
        if Instant::now() >= deadline {
            println!(
                "    [driver] TIMEOUT after {:?} waiting for: {label}",
                timeout
            );
            return (collected, false);
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn send(agent: &AgentClient, target: &str, body: &str) {
    println!("    >>DRIVER>> {body}");
    if let Err(e) = agent.send_dm(target, body).await {
        eprintln!("[driver] send failed: {e:#}");
    }
}

/// (Re)connect, reusing the persisted store (room + crypto state). OIDC access
/// tokens are short-lived (~300s) and this example — unlike the daemon — has no
/// rotation loop, so we reconnect before each test to get a fresh token;
/// otherwise long `claude -p` waits outlive the token and every send/sync 401s.
async fn connect_agent(args: &Args) -> AgentClient {
    let agent = AgentClient::connect(AgentConfig {
        key_file: args.key_file.clone(),
        siwx_url: args.siwx_url.clone(),
        matrix_url: args.matrix_url.clone(),
        client_id: None,
        redirect_uri: None,
        store_dir: args.store_dir.clone(),
        // None → connect() derives a stable device_id from the DID.
        device_id: None,
    })
    .await
    .expect("driver failed to connect");
    // Settle a few syncs so device-key/Megolm state re-establishes before we
    // send. A reconnect mints a fresh session; the FIRST message sent
    // immediately after can be undecryptable by the daemon (its copy of our
    // outbound key hasn't synced yet), so it silently drops it (UTD → not a
    // message event → no dispatch). These syncs exchange keys first.
    for _ in 0..3 {
        let _ = agent.sync_once().await;
    }
    agent
}

/// True if the agent's access token is within 60s of expiry (or already past).
fn expiring(agent: &AgentClient) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    agent.expires_at_unix().saturating_sub(now) < 60
}

/// Absorb the first-message-after-reconnect Megolm race: send a benign prompt
/// and wait for any reply, so the graded prompt that follows is never the
/// (race-prone) first message on a freshly reconnected session.
async fn warmup_ready(
    agent: &AgentClient,
    room_id: &str,
    seen: &mut HashSet<String>,
    channel: &str,
) {
    println!("    [driver] warmup after reconnect (absorb re-key race)...");
    send(
        agent,
        channel,
        "(e2e readiness check — please reply: ready)",
    )
    .await;
    let _ = wait_for(
        agent,
        room_id,
        seen,
        channel,
        "warmup",
        |_| true,
        Duration::from_secs(120),
    )
    .await;
}

/// Reconnect+warmup only if the token is near expiry — minimises reconnects (so
/// most tests run on the same connection with no re-key race) while never
/// letting a long `claude -p` wait outlive the token.
async fn refresh_if_needed(
    agent: AgentClient,
    args: &Args,
    room_id: &str,
    seen: &mut HashSet<String>,
    channel: &str,
) -> AgentClient {
    if !expiring(&agent) {
        return agent;
    }
    println!("[driver] token near expiry — reconnecting + warmup");
    let fresh = connect_agent(args).await;
    warmup_ready(&fresh, room_id, seen, channel).await;
    fresh
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,aqua_matrix_agent=warn".into()),
        )
        .try_init()
        .ok();

    let args = Args::parse();
    let channel = args.target.clone();

    let mut agent = connect_agent(&args).await;
    println!(
        "[driver] connected as {} ({})",
        agent.user_id(),
        agent.did()
    );
    println!("[driver] target channel: {channel}");

    // --- Converge on a single shared DM room ---------------------------------
    // The invite must already exist and the daemon must already have joined and
    // emitted its `[hello]` (the daemon only joins invites + says hello at the
    // start of its FIRST cycle, and ignores anything sent before its watermark).
    // So we (a) ensure the room exists, then (b) wait until we actually observe
    // a message FROM the daemon — proof it joined and set its watermark — before
    // sending any graded prompt. Seeing the hello also teaches us the daemon's
    // device keys, so our subsequent sends are decryptable by it.
    // Pre-sync BEFORE sending anything: a fresh process must load m.direct +
    // room membership from the server first, otherwise send_dm's room lookup
    // misses the existing room and creates a brand-new one (and the daemon then
    // joins yet another room). With the pre-sync, we reuse the single room the
    // one-shot invite created.
    println!("[driver] pre-sync to load account data + room membership...");
    for _ in 0..6 {
        let _ = agent.sync_once().await;
        let _ = agent.join_invited_rooms().await;
        tokio::time::sleep(POLL).await;
    }
    let mut room_id = None;
    for i in 0..40 {
        let _ = agent.sync_once().await;
        if let Ok(Some(r)) = agent.dm_room_id(&channel).await {
            println!("[driver] reusing existing DM room after ~{}s: {r}", i * 3);
            room_id = Some(r);
            break;
        }
        // No room yet — create it (also (re)invites the daemon).
        send(
            &agent,
            &channel,
            "[driver] e2e session setup — establishing room",
        )
        .await;
        tokio::time::sleep(POLL).await;
    }
    let room_id = room_id.expect("DM room never resolved — is the daemon's invite pending?");

    // NOTE: we deliberately do NOT wait for a decryptable hello here. The
    // daemon's hello is often UTD on our side (it sends it immediately on
    // joining, before it has queried our device keys), and `messages()` drops
    // an encrypted-but-undecryptable event rather than surfacing it — so a
    // hello-wait can hang even though the daemon has joined. Instead we settle
    // membership/key-query with a few syncs and let Test 0 be the real liveness
    // gate: if the bidirectional round-trip fails, we abort before grading.
    println!("[driver] settling membership + key queries...");
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..6 {
        let _ = agent.sync_once().await;
        tokio::time::sleep(POLL).await;
    }
    for m in agent.messages(&room_id, 40).await.unwrap_or_default() {
        seen.insert(m.event_id);
    }

    // --- Test 0: liveness round-trip (proves bidirectional decryption) -------
    println!("\n===TEST 0: liveness===");
    agent = refresh_if_needed(agent, &args, &room_id, &mut seen, &channel).await;
    send(&agent, &channel, "Reply with exactly: PONG-OK").await;
    let (t0, t0_ok) = wait_for(
        &agent,
        &room_id,
        &mut seen,
        &channel,
        "t0",
        |b| b.contains("PONG-OK") || b.to_lowercase().contains("pong"),
        Duration::from_secs(240),
    )
    .await;
    let t0_utd = t0.iter().any(|m| m.body == "[unable to decrypt]");
    if !t0_ok {
        println!("===VERDICT T0: FAIL=== (no decryptable PONG; UTD seen: {t0_utd})");
        println!("\n[driver] aborting — transport not healthy, graded tests would be meaningless.");
        return;
    }
    println!("===VERDICT T0: PASS=== (clean bidirectional round-trip)");

    // --- Test 1: Phase A approve ---------------------------------------------
    println!("\n===TEST 1: Phase A approve (rm canary, reply yes)===");
    agent = refresh_if_needed(agent, &args, &room_id, &mut seen, &channel).await;
    let approve_before = exists(&args.approve_canary);
    send(&agent, &channel, &format!("rm {}", args.approve_canary)).await;
    let (_, got_confirm) = wait_for(
        &agent,
        &room_id,
        &mut seen,
        &channel,
        "t1-plan",
        |b| b.contains("[confirm]"),
        Duration::from_secs(240),
    )
    .await;
    if got_confirm {
        send(&agent, &channel, "yes").await;
        // execution result: any new non-confirm channel message
        let _ = wait_for(
            &agent,
            &room_id,
            &mut seen,
            &channel,
            "t1-exec",
            |b| !b.contains("[confirm]"),
            Duration::from_secs(240),
        )
        .await;
    }
    // let the rm settle
    for _ in 0..3 {
        let _ = agent.sync_once().await;
        tokio::time::sleep(POLL).await;
    }
    let approve_after = exists(&args.approve_canary);
    let t1_pass = got_confirm && approve_before && !approve_after;
    println!(
        "===VERDICT T1: {}=== (got [confirm]={got_confirm}, canary before={approve_before}, after={approve_after}; expected deleted)",
        if t1_pass { "PASS" } else { "FAIL" }
    );

    // --- Test 2: Phase A deny ------------------------------------------------
    println!("\n===TEST 2: Phase A deny (rm canary, reply no)===");
    agent = refresh_if_needed(agent, &args, &room_id, &mut seen, &channel).await;
    let deny_before = exists(&args.deny_canary);
    send(&agent, &channel, &format!("rm {}", args.deny_canary)).await;
    let (_, got_confirm2) = wait_for(
        &agent,
        &room_id,
        &mut seen,
        &channel,
        "t2-plan",
        |b| b.contains("[confirm]"),
        Duration::from_secs(240),
    )
    .await;
    let mut got_abort = false;
    if got_confirm2 {
        send(&agent, &channel, "no").await;
        let (_, aborted) = wait_for(
            &agent,
            &room_id,
            &mut seen,
            &channel,
            "t2-abort",
            |b| b.contains("[aborted]"),
            Duration::from_secs(240),
        )
        .await;
        got_abort = aborted;
    }
    for _ in 0..3 {
        let _ = agent.sync_once().await;
        tokio::time::sleep(POLL).await;
    }
    let deny_after = exists(&args.deny_canary);
    // Grade on observable behaviour: the gate fired ([confirm]) and the file
    // survived after `no`. The trailing `[aborted]` text is a courtesy message
    // and is reported for information, but not required — a single streamed
    // event is occasionally lost to an incremental-sync drop, and demanding it
    // would fail a run whose actual deny behaviour was correct.
    let t2_pass = got_confirm2 && deny_before && deny_after;
    println!(
        "===VERDICT T2: {}=== (got [confirm]={got_confirm2}, canary before={deny_before}, after={deny_after}; expected survives; [aborted] text seen={got_abort})",
        if t2_pass { "PASS" } else { "FAIL" }
    );

    // --- Test 3: Phase B ask_human -------------------------------------------
    println!("\n===TEST 3: Phase B ask_human (mid-run question, reply teal)===");
    agent = refresh_if_needed(agent, &args, &room_id, &mut seen, &channel).await;
    send(
        &agent,
        &channel,
        "Use your ask_human tool to ask me for my favorite color, then reply with a one-line compliment about that color.",
    )
    .await;
    let (_, got_ask) = wait_for(
        &agent,
        &room_id,
        &mut seen,
        &channel,
        "t3-ask",
        |b| b.contains("[ask]"),
        Duration::from_secs(240),
    )
    .await;
    let mut t3_final_mentions_teal = false;
    if got_ask {
        send(&agent, &channel, "teal").await;
        let (msgs, _) = wait_for(
            &agent,
            &room_id,
            &mut seen,
            &channel,
            "t3-final",
            |b| !b.contains("[ask]") && b.to_lowercase().contains("teal"),
            Duration::from_secs(240),
        )
        .await;
        t3_final_mentions_teal = msgs
            .iter()
            .any(|m| !m.body.contains("[ask]") && m.body.to_lowercase().contains("teal"));
    }
    let t3_pass = got_ask && t3_final_mentions_teal;
    println!(
        "===VERDICT T3: {}=== (got [ask]={got_ask}, final mentions teal={t3_final_mentions_teal})",
        if t3_pass { "PASS" } else { "FAIL" }
    );

    // --- Summary -------------------------------------------------------------
    println!("\n===SUMMARY===");
    println!(
        "T0 liveness        : {}",
        if t0_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "T1 Phase A approve : {}",
        if t1_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "T2 Phase A deny    : {}",
        if t2_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "T3 Phase B ask     : {}",
        if t3_pass { "PASS" } else { "FAIL" }
    );
    let all = t0_ok && t1_pass && t2_pass && t3_pass;
    println!("OVERALL            : {}", if all { "PASS" } else { "FAIL" });
}
