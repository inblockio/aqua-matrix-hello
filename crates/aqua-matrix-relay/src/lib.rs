//! Generic Matrix agent daemon.
//!
//! This crate owns the *transport lifecycle* — authenticate via siwx-oidc,
//! connect to Matrix, stream-sync, rotate the client ahead of token expiry,
//! deduplicate inbound messages by a timestamp watermark that persists across
//! rotations AND process restarts (so a DM arriving in the rotation gap, or
//! while the daemon was down, isn't lost), shut down
//! cleanly on SIGTERM/SIGINT, and exit cleanly after repeated connect failures
//! so systemd can self-heal. It knows nothing about *what an agent does* with a
//! message.
//!
//! To build a new agent you implement [`MessageHandler`] and call
//! [`run_daemon`]. That's the whole surface — no Matrix types appear in the
//! trait, so a handler author never touches matrix-sdk directly. See
//! `examples/echo_agent.rs` for a complete ~30-line agent.
//!
//! matrix-sdk 0.17's deeply-nested async types overflow rustc's default
//! Send-bound recursion budget when we spawn `client.sync(...)` in a tokio
//! task (the same reason the agent lib raises it).
#![recursion_limit = "256"]
//!
//! The transport (siwx-oidc + Matrix) is intentionally NOT abstracted: this
//! crate's identity is "DID-authenticated, E2EE Matrix agent template," and a
//! `Transport` trait would dilute that. The seam is at the message boundary,
//! not the wire.
//!
//! ## Lifecycle (per client cycle)
//!
//! The outer loop in [`run_daemon`] builds a fresh [`AgentClient`] (which hits
//! the refresh-grant path, preserving `device_id` and the crypto store), then:
//!   1. joins any pending invites,
//!   2. sends the handler's one-time `hello()` on the first cycle only,
//!   3. upserts the fleet-registry entry,
//!   4. runs a sync stream + optional periodic tick until the token nears
//!      expiry, then drops the client and loops to rotate.
//!
//! This mirrors the matrix-sdk reality that the `Client` has no public API to
//! swap an access token in place; rotating the whole client ~30 s before expiry
//! is what avoids the `M_UNKNOWN_TOKEN` sync wedge.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;

use matrix_sdk::{
    config::SyncSettings,
    room::Room,
    ruma::{
        api::client::receipt::create_receipt::v3::ReceiptType,
        events::{
            receipt::ReceiptThread,
            room::{
                member::{MembershipState, StrippedRoomMemberEvent},
                message::{MessageType, OriginalSyncRoomMessageEvent},
            },
        },
    },
};

// Re-export everything a handler crate needs so it can depend on ONLY this
// crate (plus tokio for its `main`). A new agent never imports matrix-sdk.
// ReplyStream / TypingGuard let handlers stream answers and show "typing…".
// MediaHandle / MediaKind ride on [`InboundMedia`] so a handler can name an
// attachment's kind and download it without touching matrix-sdk.
pub use aqua_matrix_agent::{
    is_unknown_token, load_dotenv, AgentClient, AgentConfig, MediaHandle, MediaKind, ReplyStream,
    TypingGuard, WorkItem, WorkJournal, WorkState,
};
pub use async_trait::async_trait;

mod media;

/// Rotate the client `REFRESH_GUARD_SECS` before the access token expires. 30 s
/// gives the refresh-grant round trip + a fresh initial sync ample headroom
/// inside the (typically 300 s) token TTL.
const REFRESH_GUARD_SECS: u64 = 30;
/// Minimum sleep between rotations, so a token that arrived near expiry still
/// gets one full cycle instead of hammering siwx-oidc.
const MIN_CYCLE_SECS: u64 = 15;
/// After this many consecutive [`AgentClient::connect`] failures, exit so
/// systemd's `Restart=always` brings up a fresh process. The connect path can
/// accumulate matrix-sdk / SQLite resources on partial failures; a fresh
/// process resets that. `StartLimitBurst` still guards against runaway
/// restarts.
const MAX_CONNECT_FAILURES: u32 = 3;

/// An inbound attachment (image / audio / voice / video / file), decoded from a
/// Matrix media event for a [`MessageHandler`].
///
/// The metadata is enough to decide *whether* to fetch the bytes; the actual
/// (decrypted) bytes are pulled on demand via
/// [`AgentClient::download_media`](aqua_matrix_agent::AgentClient::download_media)
/// or [`download_media_to_temp`](aqua_matrix_agent::AgentClient::download_media_to_temp),
/// passing [`handle`](Self::handle). All of this without the handler naming a
/// Matrix type — the `MediaSource` is sealed inside the [`MediaHandle`].
pub struct InboundMedia {
    /// Which kind of attachment this is (an `m.audio` with the MSC3245 voice
    /// marker reports [`MediaKind::Voice`], not [`MediaKind::Audio`]).
    pub kind: MediaKind,
    /// The attachment's filename (or the event body when no filename was set).
    pub filename: String,
    /// Declared content-type, when the sender provided one.
    pub mimetype: Option<String>,
    /// Declared size in bytes, when known.
    pub size: Option<u64>,
    /// Playback duration in milliseconds for audio/voice/video, when known.
    pub duration_ms: Option<u64>,
    /// Pixel width for images/video, when known.
    pub width: Option<u64>,
    /// Pixel height for images/video, when known.
    pub height: Option<u64>,
    /// True iff this is a voice message (carries the MSC3245 `voice` marker).
    pub is_voice: bool,
    /// Voice-message amplitude bars (`0..=1024` each), when present.
    pub waveform: Option<Vec<u16>>,
    /// Opaque handle to fetch the bytes; pass to `AgentClient::download_media`.
    pub handle: MediaHandle,
}

/// The kind of call-signaling event observed in the DM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallSignal {
    /// Legacy 1:1 VoIP invite (`m.call.invite`).
    Invite,
    /// MatrixRTC / Element Call ring (`m.call.notify`, MSC4075) — the signal
    /// Element X emits to make a peer's client show an incoming call.
    Ring,
    /// A call ended (`m.call.hangup`).
    Hangup,
}

/// An inbound call-signaling event, normalized for a [`MessageHandler`].
///
/// **Signaling only.** matrix-sdk carries no WebRTC media, so this tells a
/// handler that a call was rung / invited / ended; it does NOT provide an
/// audio/video stream. Use it to react to a call (notify a human, auto-decline,
/// log, ring back via [`AgentClient::ring_call`](aqua_matrix_agent::AgentClient::ring_call)),
/// not to join media.
#[derive(Clone, Debug)]
pub struct InboundCall {
    /// Which signal this is.
    pub signal: CallSignal,
    /// The call/session id the signal carries.
    pub call_id: String,
    /// The MXID that sent the signal.
    pub sender_mxid: String,
    /// The room the signal arrived in.
    pub room_id: String,
}

/// One inbound message, decoded from Matrix for a [`MessageHandler`].
///
/// Borrowed fields point at the live sync event (or a local owned by
/// [`dispatch`]) for the duration of the `handle_message` call; nothing borrowed
/// here outlives it. A media message (image/audio/voice/video/file) carries
/// [`media`](Self::media) — and `body` then holds the caption text (possibly
/// empty), while the filename and metadata live on the [`InboundMedia`].
pub struct InboundMessage<'a> {
    pub sender_mxid: &'a str,
    // SEAM(aqua-security): user proxy key. `sender_did` is `None` this phase; it
    // is the DID allow/deny key and the anchor for a future user-minted
    // proxy/delegation key. That key may ride here as a new field OR arrive via
    // existing Matrix message artefacts (event signatures, `m.room.member`
    // state, custom content keys) — and Matrix artefacts may well suffice, so no
    // new field is added now. This lives where messages are parsed, not at the
    // container-auth layer.
    pub sender_did: Option<String>,
    pub event_id: &'a str,
    pub room_id: &'a str,
    pub timestamp_ms: u64,
    pub msgtype: &'a str, // "m.text", "m.image", "m.audio", …
    pub body: &'a str,
    /// `Some` for an attachment message; carries the kind/metadata and a handle
    /// to download the (decrypted) bytes. `None` for a plain text message.
    pub media: Option<InboundMedia>,
}

/// A concrete agent backend. The relay owns the Matrix lifecycle; the handler
/// owns "what to do with a message" and "what to do on each tick".
///
/// All methods are `&self`; the handler is shared (`Arc`) across the sync
/// stream and every spawned task, so keep interior state behind `Mutex`/atomics
/// if you need it. `handle_message` should return quickly — spawn a task for
/// slow work (an LLM call, a subprocess) so the sync stream keeps flowing.
#[async_trait]
pub trait MessageHandler: Send + Sync + 'static {
    /// Logical role for the fleet registry, e.g. `"heartbeat"`, `"claude-channel"`.
    fn role(&self) -> &str;

    /// systemd unit supervising this agent, recorded in the registry entry.
    /// `None` for ad-hoc runs with no supervising unit.
    fn systemd_unit(&self) -> Option<&str> {
        None
    }

    /// Human-readable Matrix profile display name set on first connect, so
    /// people see an alias (e.g. "claude-channel") instead of the raw
    /// DID-derived MXID. Defaults to [`role`](Self::role); override for a
    /// friendlier label.
    fn display_name(&self) -> String {
        self.role().to_string()
    }

    /// Optional path to a local image file set as the agent's Matrix profile
    /// avatar on first connect, mirroring [`display_name`](Self::display_name).
    /// `None` (the default) leaves the avatar untouched, so existing backends
    /// are unaffected. Inside a container this is typically a read-only mount
    /// such as `/agent/avatar.png`.
    fn avatar_path(&self) -> Option<String> {
        None
    }

    /// One-time greeting DM'd to `target` on the first successful connect.
    /// `None` stays silent.
    fn hello(&self, _agent: &AgentClient) -> Option<String> {
        None
    }

    /// Called once the `hello` DM has been CONFIRMED sent (first connect only).
    /// Lets a handler durably record that the greeting was delivered, so a
    /// transient send failure (for example a stale-token first cycle, which is
    /// then fixed by a restart) never advances any "already greeted" state on a
    /// delivery that did not actually land. Default: no-op.
    fn hello_delivered(&self) {}

    /// Periodic tick interval. `None` (the default) disables the timer; the
    /// daemon then only reacts to inbound messages.
    fn tick_interval(&self) -> Option<Duration> {
        None
    }

    /// Called every [`tick_interval`](Self::tick_interval) (only when it is
    /// `Some`). The default is a no-op.
    async fn on_tick(&self, _agent: &AgentClient, _target: &str) {}

    /// DID/MXID allow-deny SEAM. Default == today's exact behavior (single
    /// target, ASCII-case-insensitive — see [`mxid_authorized`] for why that is
    /// both correct and safe against impersonation). [`dispatch`] and
    /// `register_invite_autojoin` call THIS instead of the inline equality check.
    /// SEAM(aqua-security): this is the white/blacklist hook keyed on DIDs — a
    /// future signature will take `sender_did: Option<&str>` plus a per-template
    /// allow/deny policy object (BOTH an allow-list AND a deny-list); the bool
    /// default stays `{target}` this phase so behavior is unchanged.
    fn authorize(&self, sender_mxid: &str, target: &str) -> bool {
        mxid_authorized(sender_mxid, target)
    }

    /// Handle one inbound text message from `target`. The relay has already
    /// confirmed the sender and deduplicated by timestamp watermark, so this
    /// fires at most once per message. Now takes a structured message and
    /// returns `Result` so the relay owns uniform error logging (the relay
    /// still never unwinds; it logs the `Err`).
    async fn handle_message(
        &self,
        agent: &AgentClient,
        target: &str,
        msg: &InboundMessage<'_>,
    ) -> anyhow::Result<()>;

    /// Does this handler take ownership of completing the durable work-journal
    /// item itself (via [`AgentClient::record_reply`]/[`AgentClient::mark_delivered`])?
    ///
    /// Default `false`: the handler answers synchronously inside `handle_message`,
    /// so the relay auto-completes the journal item when `handle_message` returns
    /// `Ok`. Override to `true` for a handler that spawns a detached task (e.g. a
    /// long `claude -p` turn) — `handle_message` returns *before* the answer
    /// exists, so the relay must NOT auto-complete; the handler signals completion
    /// when its task actually finishes. Getting this wrong drops the durable
    /// guarantee (auto-complete erases the inbox item before it is answered).
    fn owns_completion(&self) -> bool {
        false
    }

    /// Handle an inbound call-signaling event (invite / Element-Call ring /
    /// hangup) from `target`, already sender-authorized by the relay. The
    /// default is a no-op, so existing handlers are unaffected.
    ///
    /// **Signaling only** — there is no media stream (see [`InboundCall`]). React
    /// to the call (notify a human, auto-decline, log, ring back via
    /// [`AgentClient::ring_call`](aqua_matrix_agent::AgentClient::ring_call)); you
    /// cannot join audio/video from here. Unlike `handle_message`, a call event is
    /// not deduplicated by the watermark, so a recent signal may re-fire after a
    /// client rotation/restart — keep `on_call` idempotent.
    async fn on_call(&self, _agent: &AgentClient, _target: &str, _call: &InboundCall) {}
}

/// Canonical peer-authorization check: does `sender_mxid` denote the SAME Matrix
/// user as the configured `target`?
///
/// This is the relay's whole firewall: a consultant only auto-joins rooms its
/// bound peer invites it to, and only replies to that peer. Getting the equality
/// wrong in either direction is a security/correctness bug — too strict silently
/// drops the real peer; too loose lets an impostor in.
///
/// **Why ASCII-case-insensitive is CORRECT.** Our peers' MXID localparts encode
/// `did:key` / `did:pkh` identifiers whose base58/hex payload is case-significant
/// at the DID layer, so a configured `target` derived from a mixed-case DID can
/// carry uppercase letters (e.g. `@did-key-zDnaef1WiYi9AX…`). But Synapse
/// **canonicalises every MXID localpart to lowercase**: it is what lands in the
/// `sender` / `state_key` of every event the relay sees (verified against the
/// live agents' state stores — every `sender` field is lowercase, including each
/// agent's own `whoami`-resolved `user_id`). So an exact compare of a lowercased
/// `ev.sender` against a mixed-case `target` would reject EVERY message from such
/// a peer. Folding ASCII case closes that gap.
///
/// **Why it does NOT weaken the firewall.** The folding is safe precisely
/// *because* Synapse lowercases localparts: two MXIDs that differ only in ASCII
/// case can never be two DISTINCT accounts — they canonicalise to the same user,
/// so there is no separate "impostor differing only in case" for the fold to
/// admit. The relay never receives an `ev.sender` that still carries uppercase;
/// the only uppercase in play is on the *configured* side (`target`), under the
/// operator's control. We fold **ASCII only** (`eq_ignore_ascii_case`), matching
/// the ASCII-only Matrix localpart grammar and Synapse's ASCII lowercasing — a
/// Unicode case fold could conflate codepoints Synapse keeps distinct, so we
/// deliberately avoid it. Net: the set of accepted senders is exactly `{target}`
/// canonicalised — never broader.
pub fn mxid_authorized(sender_mxid: &str, target: &str) -> bool {
    sender_mxid.eq_ignore_ascii_case(target)
}

/// True for a "near miss": `sender` is NOT authorized under the exact
/// (case-sensitive) compare yet WOULD match `target` case-insensitively. Today
/// this should never fire on a real `ev.sender` (Synapse already lowercased it),
/// so logging it at authorize time turns a previously-silent casing surprise
/// into a visible WARN — the canary that the "Synapse lowercases" assumption
/// (or a `target` typo) has broken.
fn is_case_only_mismatch(sender_mxid: &str, target: &str) -> bool {
    sender_mxid != target && sender_mxid.eq_ignore_ascii_case(target)
}

/// Emit a WARN when an inbound `kind` ("message" / "invite" / "call") is dropped
/// from a sender that is a case-only near-miss of `target`. With the default
/// `authorize` (which folds case) this branch is unreachable — a near-miss IS
/// authorized — so the only way to reach it is a handler that OVERRODE
/// `authorize` to compare case-sensitively. Logging it makes such a silent
/// casing-mismatch drop visible instead of invisible, satisfying the "never
/// silent again" requirement regardless of the handler's policy.
///
/// Takes `role` (not the handler) so the call sites can pass `handler.role()`
/// without wrestling the `Arc<H>` they hold into a `&H`.
fn warn_on_case_only_drop(sender_mxid: &str, target: &str, role: &str, kind: &str) {
    if is_case_only_mismatch(sender_mxid, target) {
        tracing::warn!(
            "{role}: dropped {kind} from {sender_mxid:?}: it matches target {target:?} only \
             up to ASCII case, but this handler's authorize() rejected it. A peer whose \
             MXID differs from the configured target only in case is being IGNORED — \
             check the target casing."
        );
    }
}

/// Validate the configured `target` at startup and log loudly on anything that
/// would make the firewall silently misbehave. Non-fatal by design: a consultant
/// with a slightly-off target should still come up (and stay observable) rather
/// than crash-loop, but the operator gets an unmistakable WARN.
///
/// Checks, in order:
///  1. Structural: a Matrix user ID is `@localpart:server`. A `target` missing
///     the leading `@` or the `:server` is malformed and will match nothing.
///  2. Canonical casing: Synapse delivers `ev.sender` lowercased, so a `target`
///     whose localpart carries uppercase can ONLY ever match via the
///     case-insensitive fold. That still works, but it means the configured form
///     differs from what the server delivers — worth surfacing so a genuine typo
///     isn't mistaken for the expected DID mixed-casing.
///
/// Returns `true` iff the target is well-formed (callers may log/proceed
/// regardless; the bool is for tests and future fail-closed policies).
pub fn validate_target(target: &str, role: &str) -> bool {
    let well_formed = match target.split_once(':') {
        Some((user, server)) => {
            target.starts_with('@') && user.len() > 1 && !server.is_empty()
        }
        None => false,
    };
    if !well_formed {
        tracing::warn!(
            "{role}: configured target {target:?} is not a well-formed Matrix user ID \
             (@localpart:server); the relay will authorize NO sender against it and the \
             consultant will silently reply to no one — check AGENT_TARGET / .target"
        );
        return false;
    }
    // Localpart is everything between '@' and the first ':'.
    let localpart = &target[1..target.find(':').unwrap_or(target.len())];
    if localpart.chars().any(|c| c.is_ascii_uppercase()) {
        tracing::warn!(
            "{role}: configured target {target:?} has an UPPERCASE localpart, but Synapse \
             canonicalises MXIDs to lowercase, so inbound events arrive lowercased. \
             Authorization still works (it folds ASCII case), but the configured form \
             differs from the delivered form — confirm this is the intended DID casing \
             and not a typo. Canonical (delivered) form: {:?}",
            target.to_ascii_lowercase()
        );
    }
    true
}

/// Run the agent daemon forever: connect, serve, rotate, repeat. Only returns
/// by `std::process::exit` after [`MAX_CONNECT_FAILURES`] consecutive connect
/// failures (so systemd restarts a clean process).
pub async fn run_daemon<H: MessageHandler>(config: AgentConfig, target: &str, handler: H) {
    let handler = Arc::new(handler);
    let target = Arc::new(target.to_string());

    tracing::info!(
        "{} daemon starting (target: {}, sync: stream, refresh-guard: {}s)",
        handler.role(),
        target,
        REFRESH_GUARD_SECS,
    );

    // Validate the configured peer at startup so a malformed or non-canonical
    // target is surfaced LOUDLY once, rather than manifesting as a consultant
    // that silently replies to no one. Non-fatal: we log and continue.
    validate_target(&target, handler.role());

    // The inbound-message dedupe watermark lives ACROSS cycles AND restarts:
    // loaded from `<store>/inbound-watermark` here (seeded to "now" only when
    // the file is absent or unparsable) and persisted by [`dispatch`] on every
    // advance. The cross-cycle carry-forward is what stops the rotation gap
    // from losing a message: when the client rotates (~30 s before token
    // expiry) the new cycle's initial sync re-delivers recent timeline; with a
    // per-cycle "now" watermark a DM that landed during the gap (its ts is
    // just older than the new cycle's start) would look like backlog and be
    // dropped. Carrying the watermark means a gap message (ts > watermark) is
    // dispatched exactly once, while already-seen messages (ts <= watermark)
    // stay skipped.
    //
    // The cross-restart persistence extends the same guarantee to process
    // restarts (crash-exit after MAX_CONNECT_FAILURES, `systemctl restart`,
    // host reboot): the next process resumes from the last processed message
    // instead of re-seeding to "now" and silently skipping everything that
    // was delivered while the daemon was down.
    let watermark = Arc::new(Watermark::load_or_seed(&config.store_dir));

    // Durable work-journal: the inbox+outbox that makes every accepted message a
    // promise (answered-or-errored, delivery confirmed) across restarts AND token
    // rotation. The watermark stops sync from re-delivering an already-seen event;
    // the journal is what guarantees an accepted event is actually *completed*
    // (answered + delivered) — it persists `Pending` (needs the handler to run)
    // and `ToDeliver { text }` (answer produced, delivery owed) until done.
    // `recycle` lets a handler request an immediate reconnect so a
    // journalled-but-undelivered reply is redelivered on a fresh token in seconds,
    // not at the next scheduled rotation.
    let journal = Arc::new(WorkJournal::load_or_empty(&config.store_dir));
    let recycle = Arc::new(Notify::new());
    let mut replay_pending = true;

    // Trap SIGTERM/SIGINT once and fan it out via a Notify so every cycle can
    // unwind cleanly. `podman stop`/`systemctl stop` send SIGTERM and SIGKILL
    // after a grace period; handling it lets us abort the in-flight sync and
    // return from `run_daemon` (so `main` exits 0) well before the SIGKILL.
    // SIGINT (Ctrl-C) is treated identically for local runs.
    let shutdown = Arc::new(Notify::new());
    spawn_shutdown_listener(shutdown.clone());

    let mut first_cycle = true;
    let mut consecutive_failures: u32 = 0;
    loop {
        let mut agent = match AgentClient::connect(config.clone()).await {
            Ok(a) => {
                consecutive_failures = 0;
                a
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::error!(
                    "{}: AgentClient::connect failed ({consecutive_failures}/{MAX_CONNECT_FAILURES}): {e:#}",
                    handler.role(),
                );
                if consecutive_failures >= MAX_CONNECT_FAILURES {
                    tracing::error!(
                        "{}: {MAX_CONNECT_FAILURES} consecutive connect failures; exiting for systemd Restart=always (avoids in-process resource accumulation)",
                        handler.role(),
                    );
                    std::process::exit(1);
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        // Sync once first so a pending invite is actually visible: right after
        // connect the initial sync may not yet carry an invite the peer sent
        // moments earlier, and `join_invited_rooms` would then join nothing.
        if let Err(e) = agent.sync_once().await {
            tracing::warn!("{}: pre-join sync_once failed: {e:#}", handler.role());
        }

        // Join pending invites, then record each joined room as the DM with our
        // peer. A freshly connected client has empty `m.direct` and an
        // unpopulated member list, so without this the first outbound message
        // (the hello below) fails to resolve the shared room and `create_dm`
        // spawns a DUPLICATE — which, against a programmatic peer, splits the two
        // sides into separate rooms and breaks Megolm key exchange (in
        // production it leaves stray empty rooms). The peer is the only party
        // that DMs us, so any room it invited us to IS the DM room.
        match agent.join_invited_rooms().await {
            Ok(joined) => {
                for room_id in &joined {
                    if let Err(e) = agent.mark_dm(room_id, &target).await {
                        tracing::warn!("{}: mark_dm({room_id}) failed: {e:#}", handler.role());
                    } else {
                        tracing::info!("{}: marked joined room {room_id} as DM with peer", handler.role());
                    }
                }
            }
            Err(e) => tracing::warn!("{}: join_invited_rooms failed: {e:#}", handler.role()),
        }

        // One sync so the peer's device keys are known before we encrypt the
        // hello (otherwise the hello is undecryptable on their side until the
        // next round-trip). Best-effort.
        if let Err(e) = agent.sync_once().await {
            tracing::warn!("{}: settle sync_once failed: {e:#}", handler.role());
        }

        // Attach the durable journal + recycle signal so a handler running on a
        // clone of this client can record/complete its replies durably.
        agent.attach_durability(journal.clone(), recycle.clone());

        // Redeliver any answer/error produced but not confirmed delivered (a
        // token-rotation failure last cycle, or a prior crash) — now on this
        // cycle's fresh token. Each confirmed send clears its journal entry; a
        // still-failing one stays for the next cycle. This is the outbound half of
        // the promise: a reply can never be silently dropped.
        drain_deliveries(&agent, &target, &journal, handler.role()).await;

        // Once per process: replay inbound messages that were accepted but never
        // answered (crash/restart mid-turn). The watermark prevents sync from
        // re-delivering them, so the journal is the only thing that can — this is
        // the inbox promise surviving a restart.
        if replay_pending {
            replay_pending = false;
            replay_inbox(&agent, &target, &handler, &journal).await;
        }

        let now = unix_now_secs();
        let ttl = agent
            .expires_at_unix()
            .saturating_sub(now)
            .saturating_sub(REFRESH_GUARD_SECS)
            .max(MIN_CYCLE_SECS);
        let refresh_deadline = tokio::time::Instant::now() + Duration::from_secs(ttl);
        tracing::info!(
            "{}: client cycle starting (token ttl {}s, rotating in {}s)",
            handler.role(),
            agent.expires_at_unix().saturating_sub(now),
            ttl,
        );

        if first_cycle {
            // Publish a human-readable alias before anything else, so the hello
            // DM and registry entry surface under a readable name rather than
            // the DID-derived MXID. Best-effort: never block startup on it.
            let alias = handler.display_name();
            if let Err(e) = agent.set_display_name(&alias).await {
                tracing::warn!("{}: set display name failed: {e:#}", handler.role());
            } else {
                tracing::info!("{}: display name set to {:?}", handler.role(), alias);
            }
            // Set the profile avatar the same way: best-effort, never blocks
            // startup. set_avatar is idempotent (skips re-upload when unchanged).
            if let Some(avatar) = handler.avatar_path() {
                match agent.set_avatar(std::path::Path::new(&avatar)).await {
                    Ok(()) => tracing::info!("{}: avatar set from {:?}", handler.role(), avatar),
                    Err(e) => tracing::warn!("{}: set avatar failed: {e:#}", handler.role()),
                }
            }
            if let Some(hello) = handler.hello(&agent) {
                // Only greet into an EXISTING DM room. If none resolves yet (the
                // peer's invite hasn't been synced/joined), sending would
                // `create_dm` a stray duplicate room and pollute m.direct — skip
                // it; the auto-join handler will pick up the real room and the
                // first real exchange establishes Megolm there anyway.
                match agent.dm_room_id(&target).await {
                    Ok(Some(_)) => {
                        if let Err(e) = agent.send_dm(&target, &hello).await {
                            tracing::warn!("{}: hello send failed: {e:#}", handler.role());
                        } else {
                            // Greeting confirmed delivered: let the handler commit
                            // any "already greeted" state now, not on a failed send.
                            handler.hello_delivered();
                        }
                    }
                    _ => tracing::info!(
                        "{}: no DM room yet; deferring hello (auto-join will converge)",
                        handler.role()
                    ),
                }
            }
            first_cycle = false;
        }

        // Upsert the fleet-registry entry on every cycle start so a freshly
        // rotated session re-announces itself promptly. Best-effort: never let a
        // registry failure perturb the daemon.
        if let Err(e) = agent
            .update_registry(handler.role(), handler.systemd_unit())
            .await
        {
            tracing::warn!("{}: registry update failed: {e:#}", handler.role());
        }

        let exit = run_cycle(
            &agent,
            &target,
            &handler,
            refresh_deadline,
            watermark.clone(),
            journal.clone(),
            &recycle,
            &shutdown,
        )
        .await;
        if exit == "shutdown" {
            // `run_cycle` already aborted the in-flight sync task before
            // returning the sentinel, so nothing is left dangling. Return so
            // `main` falls through and the process exits 0 before SIGKILL.
            tracing::info!("{}: received SIGTERM; shutting down", handler.role());
            return;
        }
        tracing::info!("{}: cycle ended ({exit}); reconnecting", handler.role());
    }
}

/// Spawn a detached task that awaits SIGTERM or SIGINT and then notifies
/// `shutdown`. Whichever signal fires first triggers the same clean shutdown
/// path; subsequent signals are irrelevant (we're already unwinding).
/// If installing a handler fails we log and leave that signal untrapped rather
/// than abort startup — the other signal (and systemd's SIGKILL) still apply.
fn spawn_shutdown_listener(shutdown: Arc<Notify>) {
    use tokio::signal::unix::{signal, SignalKind};
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to install SIGTERM handler: {e:#}");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to install SIGINT handler: {e:#}");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received"),
            _ = sigint.recv() => tracing::info!("SIGINT received"),
        }
        // `notify_one` both wakes a waiter that's already parked AND stores a
        // permit if none is, so a cycle that hasn't yet reached its
        // `notified()` await still observes shutdown on its next call. Exactly
        // one cycle runs at a time, so a single permit suffices.
        shutdown.notify_one();
    });
}

/// Run one client cycle: register handlers, sync until the rotation deadline
/// (or sync end, or shutdown), then abort the sync task and report why it ended.
///
/// `watermark` is the cross-cycle inbound-message dedupe key, owned by
/// [`run_daemon`] and passed in (not created here). It is loaded once at
/// daemon start from its file in the store dir (falling back to "now" when no
/// usable file exists, so only the very first run ignores pre-startup
/// backlog); every cycle reuses the SAME watermark, so when this cycle's
/// initial sync re-delivers recent timeline after a client rotation, a message
/// that arrived in the rotation gap (ts > watermark) is dispatched exactly
/// once while already-seen messages (ts <= watermark) stay skipped.
/// [`dispatch`] still advances it monotonically (and persists each advance).
///
/// `shutdown` is fired by the daemon's SIGTERM/SIGINT listener; observing it
/// returns the `"shutdown"` sentinel so [`run_daemon`] can exit cleanly.
async fn run_cycle<H: MessageHandler>(
    agent: &AgentClient,
    target: &Arc<String>,
    handler: &Arc<H>,
    refresh_deadline: tokio::time::Instant,
    watermark: Arc<Watermark>,
    journal: Arc<WorkJournal>,
    recycle: &Notify,
    shutdown: &Notify,
) -> &'static str {
    // Collect every per-cycle event-handler handle so we can REMOVE them at cycle
    // end (see teardown below). matrix-sdk stores each handler closure inside the
    // Client, and each closure captures an `agent.clone()` — an Arc clone of that
    // same Client. That is a strong reference cycle: without removal the old Client
    // never drops on reconnect, leaking its four SQLite connection pools every
    // cycle until the fd count trips EMFILE and the connect-failure circuit breaker.
    let mut handles: Vec<matrix_sdk::event_handler::EventHandlerHandle> = Vec::new();
    handles.push(register_handler(
        agent.clone(),
        target.clone(),
        handler.clone(),
        watermark,
        journal,
    ));
    // Surface inbound call signaling (invite / Element-Call ring / hangup) to the
    // handler's `on_call`. Separate from `register_handler` because call events
    // are distinct event types, not room messages.
    handles.extend(register_call_handler(
        agent.clone(),
        target.clone(),
        handler.clone(),
    ));
    // Auto-join invites as they arrive on the sync stream (not only at cycle
    // start), so an invite the peer sends mid-cycle — or just after connect,
    // before the startup join sees it — is still joined and recorded as the DM.
    handles.push(register_invite_autojoin(
        agent.clone(),
        target.clone(),
        handler.clone(),
    ));

    let sync_client = agent.client().clone();
    let mut sync_task = tokio::spawn(async move { sync_client.sync(SyncSettings::default()).await });

    let exit = match handler.tick_interval() {
        Some(interval) => {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick — the hello (or the previous cycle's
            // last tick) just went out; let the operator see the real cadence.
            tick.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.notified() => break "shutdown",
                    _ = recycle.notified() => break "recycle",
                    _ = tokio::time::sleep_until(refresh_deadline) => break "refresh-deadline",
                    res = &mut sync_task => {
                        log_sync_end(res);
                        break "sync-ended";
                    }
                    _ = tick.tick() => {
                        handler.on_tick(agent, target).await;
                    }
                }
            }
        }
        None => {
            tokio::select! {
                biased;
                _ = shutdown.notified() => "shutdown",
                _ = recycle.notified() => "recycle",
                _ = tokio::time::sleep_until(refresh_deadline) => "refresh-deadline",
                res = &mut sync_task => {
                    log_sync_end(res);
                    "sync-ended"
                }
            }
        }
    };

    // If the sync task already completed (its `res = &mut sync_task` arm fired —
    // e.g. sync() returned on a 401), it MUST NOT be awaited again: polling a
    // finished JoinHandle panics ("JoinHandle polled after completion"). Guard on
    // is_finished() so we only abort+await while it's still running (the
    // shutdown / refresh-deadline / tick exits). A finished handle is just
    // dropped — its result was already logged by the sync-ended arm.
    if !sync_task.is_finished() {
        sync_task.abort();
        let _ = sync_task.await;
    }

    // Break the Client<->handler reference cycle: removing each handler drops the
    // stored closure (and the Arc clone of the Client it captured), so once this
    // cycle's `agent` clones fall out of scope the underlying Client — and its
    // open SQLite file handles — are finally freed instead of leaking into the
    // next cycle. (matrix-sdk has no "remove all"; we remove the handles we kept.)
    for handle in handles {
        agent.client().remove_event_handler(handle);
    }
    exit
}

fn log_sync_end(res: Result<matrix_sdk::Result<()>, tokio::task::JoinError>) {
    match res {
        Ok(Ok(_)) => tracing::warn!("matrix sync returned Ok (unexpected)"),
        Ok(Err(e)) => tracing::warn!("matrix sync error: {e:#}"),
        Err(e) => tracing::warn!("matrix sync task join error: {e:#}"),
    }
}

/// Continuously auto-join rooms we are invited to (and record them as the DM
/// with our peer), so the daemon converges on the SAME room the peer created
/// rather than `create_dm` later spawning a duplicate. Registered on the sync
/// stream so it fires whenever an invite arrives, not just at cycle start.
fn register_invite_autojoin<H: MessageHandler>(
    agent: AgentClient,
    target: Arc<String>,
    handler: Arc<H>,
) -> matrix_sdk::event_handler::EventHandlerHandle {
    let own = agent.user_id().to_string();
    let role = handler.role().to_string();
    agent.client().add_event_handler({
        let agent = agent.clone();
        move |ev: StrippedRoomMemberEvent, room: Room| {
            let agent = agent.clone();
            let target = target.clone();
            let role = role.clone();
            let handler = handler.clone();
            let own = own.clone();
            async move {
                // Only act on an invite addressed to us.
                if ev.state_key.as_str() != own
                    || ev.content.membership != MembershipState::Invite
                {
                    return;
                }
                // Invite auto-join is intentionally narrowed to the target only
                // (was: any inviter) — the default `authorize` keeps the
                // case-insensitive single-peer check. Safe under the strict
                // single-peer DM design; messaging/dispatch behavior unchanged.
                if !handler.authorize(ev.sender.as_str(), &target) {
                    warn_on_case_only_drop(ev.sender.as_str(), &target, handler.role(), "invite");
                    return;
                }
                match room.join().await {
                    Ok(()) => {
                        let room_id = room.room_id().to_string();
                        tracing::info!("{role}: auto-joined invited room {room_id}");
                        if let Err(e) = agent.mark_dm(&room_id, &target).await {
                            tracing::warn!("{role}: mark_dm({room_id}) after auto-join failed: {e:#}");
                        }
                    }
                    Err(e) => tracing::warn!("{role}: auto-join failed: {e:#}"),
                }
            }
        }
    })
}

fn register_handler<H: MessageHandler>(
    agent: AgentClient,
    target: Arc<String>,
    handler: Arc<H>,
    watermark: Arc<Watermark>,
    journal: Arc<WorkJournal>,
) -> matrix_sdk::event_handler::EventHandlerHandle {
    agent.client().add_event_handler({
        let agent = agent.clone();
        move |ev: OriginalSyncRoomMessageEvent, room: Room| {
            let agent = agent.clone();
            let target = target.clone();
            let handler = handler.clone();
            let watermark = watermark.clone();
            let journal = journal.clone();
            async move {
                dispatch(ev, room, &agent, &target, &handler, &watermark, &journal).await;
            }
        }
    })
}

/// Install sync handlers for the three call-signaling events we care about:
/// legacy `m.call.invite`/`m.call.hangup` and the MatrixRTC `m.call.notify`
/// (MSC4075) ring that Element Call emits. Each is authorized by sender and
/// forwarded to [`MessageHandler::on_call`]. (Signaling only — no media.)
// `m.call.notify` is deprecated in ruma in favour of `m.rtc.notification`, but
// it is still what current Element clients emit, so we read it deliberately.
#[allow(deprecated)]
fn register_call_handler<H: MessageHandler>(
    agent: AgentClient,
    target: Arc<String>,
    handler: Arc<H>,
) -> Vec<matrix_sdk::event_handler::EventHandlerHandle> {
    use matrix_sdk::ruma::events::call::{
        hangup::OriginalSyncCallHangupEvent, invite::OriginalSyncCallInviteEvent,
        notify::OriginalSyncCallNotifyEvent,
    };

    let client = agent.client().clone();

    let h_invite = client.add_event_handler({
        let agent = agent.clone();
        let target = target.clone();
        let handler = handler.clone();
        move |ev: OriginalSyncCallInviteEvent, room: Room| {
            let agent = agent.clone();
            let target = target.clone();
            let handler = handler.clone();
            async move {
                dispatch_call(
                    &agent,
                    &target,
                    &handler,
                    CallSignal::Invite,
                    ev.content.call_id.to_string(),
                    ev.sender.as_str(),
                    room.room_id().as_str(),
                )
                .await;
            }
        }
    });

    let h_notify = client.add_event_handler({
        let agent = agent.clone();
        let target = target.clone();
        let handler = handler.clone();
        move |ev: OriginalSyncCallNotifyEvent, room: Room| {
            let agent = agent.clone();
            let target = target.clone();
            let handler = handler.clone();
            async move {
                dispatch_call(
                    &agent,
                    &target,
                    &handler,
                    CallSignal::Ring,
                    ev.content.call_id.clone(),
                    ev.sender.as_str(),
                    room.room_id().as_str(),
                )
                .await;
            }
        }
    });

    let h_hangup = client.add_event_handler({
        move |ev: OriginalSyncCallHangupEvent, room: Room| {
            let agent = agent.clone();
            let target = target.clone();
            let handler = handler.clone();
            async move {
                dispatch_call(
                    &agent,
                    &target,
                    &handler,
                    CallSignal::Hangup,
                    ev.content.call_id.to_string(),
                    ev.sender.as_str(),
                    room.room_id().as_str(),
                )
                .await;
            }
        }
    });

    vec![h_invite, h_notify, h_hangup]
}

/// Authorize a call signal by sender and forward it to the handler's `on_call`.
async fn dispatch_call<H: MessageHandler>(
    agent: &AgentClient,
    target: &str,
    handler: &Arc<H>,
    signal: CallSignal,
    call_id: String,
    sender: &str,
    room_id: &str,
) {
    if !handler.authorize(sender, target) {
        warn_on_case_only_drop(sender, target, handler.role(), "call");
        return;
    }
    let call = InboundCall {
        signal,
        call_id,
        sender_mxid: sender.to_string(),
        room_id: room_id.to_string(),
    };
    handler.on_call(agent, target, &call).await;
}

async fn dispatch<H: MessageHandler>(
    ev: OriginalSyncRoomMessageEvent,
    room: Room,
    agent: &AgentClient,
    target: &str,
    handler: &Arc<H>,
    watermark: &Watermark,
    journal: &WorkJournal,
) {
    // Only messages from the configured peer, and only ones newer than anything
    // we've already seen this cycle. The default `authorize` compares
    // case-insensitively: Synapse canonicalises MXIDs to lowercase, so
    // `ev.sender` is lowercased, while a `--target` derived from a mixed-case
    // `did:key` is not — an exact compare would silently drop every inbound
    // message from such a peer.
    if !handler.authorize(ev.sender.as_str(), target) {
        warn_on_case_only_drop(ev.sender.as_str(), target, handler.role(), "message");
        return;
    }
    let ts_ms = u64::from(ev.origin_server_ts.0);
    if ts_ms <= watermark.get() {
        return;
    }

    // Instant "seen" acknowledgement (fire-and-forget): the user gets feedback
    // that the message landed before any handler latency. Best-effort.
    {
        let room = room.clone();
        let event_id = ev.event_id.clone();
        tokio::spawn(async move {
            let _ = room
                .send_single_receipt(ReceiptType::Read, ReceiptThread::Unthreaded, event_id)
                .await;
        });
    }

    // Text → body only. Media (image/audio/voice/video/file) → an `InboundMedia`
    // plus the caption as `body` (so a captioned image reads naturally). Other
    // msgtypes (notice, emote, location, verification…) carry nothing actionable
    // for a handler; ignore them without advancing the watermark (the ts check
    // still prevents reprocessing).
    let (body, media) = match &ev.content.msgtype {
        MessageType::Text(t) => (t.body.trim().to_string(), None),
        MessageType::Image(c) => (
            c.caption().unwrap_or("").trim().to_string(),
            Some(media::from_image(c)),
        ),
        MessageType::Audio(c) => (
            c.caption().unwrap_or("").trim().to_string(),
            Some(media::from_audio(c)),
        ),
        MessageType::Video(c) => (
            c.caption().unwrap_or("").trim().to_string(),
            Some(media::from_video(c)),
        ),
        MessageType::File(c) => (
            c.caption().unwrap_or("").trim().to_string(),
            Some(media::from_file(c)),
        ),
        _ => return,
    };

    // Advance (and persist) the watermark BEFORE dispatching: if the handler
    // (or the process) dies mid-work we must not re-trigger on the same
    // message after restart.
    watermark.advance(ts_ms);

    // Drop only a truly empty message: an attachment with no caption still has
    // `media`, so it must dispatch even though `body` is empty.
    if body.is_empty() && media.is_none() {
        return;
    }

    // Durable inbox: record the message BEFORE handling so a crash/restart
    // mid-turn replays it (the watermark above stops sync from re-delivering it,
    // so the journal is the only thing that can). `enqueue` is idempotent on
    // event_id and returns `false` if the event is already tracked — a rare
    // re-sync race where it is already in-flight (`Pending`) or answered and
    // awaiting delivery (`ToDeliver`). In that case do NOT re-dispatch: the
    // existing handler run / the cycle drain already owns it; re-running would
    // double-process (a duplicate answer).
    let newly_enqueued = journal.enqueue(WorkItem {
        event_id: ev.event_id.to_string(),
        room_id: room.room_id().to_string(),
        ts_ms,
        msgtype: ev.content.msgtype.msgtype().to_string(),
        body: body.clone(),
        state: WorkState::Pending,
    });
    if !newly_enqueued {
        tracing::debug!(
            "{}: event {} already tracked in the work-journal; not re-dispatching",
            handler.role(),
            ev.event_id
        );
        return;
    }

    let msg = InboundMessage {
        sender_mxid: ev.sender.as_str(),
        sender_did: None,
        event_id: ev.event_id.as_str(),
        room_id: room.room_id().as_str(),
        timestamp_ms: ts_ms,
        msgtype: ev.content.msgtype.msgtype(),
        body: &body,
        media,
    };

    // The relay never unwinds on a handler error: log it at `warn` and keep
    // serving. (Errors are the handler's domain; the transport stays up.)
    if let Err(e) = handler.handle_message(agent, target, &msg).await {
        tracing::warn!("{}: handle_message failed: {e:#}", handler.role());
    }

    // Completion of the durable item:
    //  - A handler that answers synchronously inside `handle_message` is DONE now,
    //    so auto-complete (covers echo/heartbeat and keeps their behaviour simple).
    //  - A handler that `owns_completion()` (claude-p spawns a detached task) has
    //    NOT answered yet; it records `ToDeliver` and marks done from its own task.
    //    Auto-completing here would erase the inbox item before it is answered.
    if !handler.owns_completion() {
        journal.mark_done(ev.event_id.as_str());
    }
}

/// Redeliver every `ToDeliver` journal entry — an answer/error that was produced
/// but whose live send was not confirmed (token rotation, a transient server
/// error, or a crash before delivery). Runs at the start of each cycle, so the
/// send uses this cycle's freshly-minted token: that IS the self-heal for the
/// token-rotation drop. A confirmed send clears the entry; a still-failing one
/// stays for the next cycle. Never re-runs the handler (the text is cached).
async fn drain_deliveries(
    agent: &AgentClient,
    target: &str,
    journal: &WorkJournal,
    role: &str,
) {
    for item in journal.pending_deliveries() {
        let WorkState::ToDeliver { text } = &item.state else {
            continue;
        };
        match agent.send_dm_chunked(target, text).await {
            Ok(_) => {
                journal.mark_done(&item.event_id);
                tracing::info!("{role}: redelivered journalled reply for {}", item.event_id);
            }
            Err(e) => tracing::warn!(
                "{role}: redelivery of {} failed (will retry next cycle): {e:#}",
                item.event_id
            ),
        }
    }
}

/// Replay inbound messages that were accepted but never answered — `Pending`
/// items left by a crash/restart mid-turn. The dedupe watermark prevents sync
/// from re-delivering them, so without this they would be silently dropped; this
/// is the inbox promise surviving a restart. Runs ONCE per process (the live sync
/// path handles everything after). Text-only: a media handle can't be re-resolved
/// across a restart, so a replayed media message carries just its caption (logged).
async fn replay_inbox<H: MessageHandler>(
    agent: &AgentClient,
    target: &str,
    handler: &Arc<H>,
    journal: &WorkJournal,
) {
    let pending = journal.pending_work();
    if pending.is_empty() {
        return;
    }
    tracing::info!(
        "{}: replaying {} unfinished inbox message(s) after restart",
        handler.role(),
        pending.len()
    );
    for item in pending {
        if item.msgtype != "m.text" {
            tracing::warn!(
                "{}: replaying non-text message {} ({}) with caption only — media not re-fetchable after restart",
                handler.role(),
                item.event_id,
                item.msgtype
            );
        }
        let msg = InboundMessage {
            sender_mxid: target,
            sender_did: None,
            event_id: &item.event_id,
            room_id: &item.room_id,
            timestamp_ms: item.ts_ms,
            msgtype: &item.msgtype,
            body: &item.body,
            media: None,
        };
        if let Err(e) = handler.handle_message(agent, target, &msg).await {
            tracing::warn!("{}: replay handle_message failed: {e:#}", handler.role());
        }
        // Mirror dispatch's completion rule: a synchronous handler is done now; an
        // owns_completion handler completes from its own (re-spawned) task.
        if !handler.owns_completion() {
            journal.mark_done(&item.event_id);
        }
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Cross-restart inbound dedupe watermark: the newest `origin_server_ts` (ms)
/// already dispatched, held in memory and mirrored to a small file inside the
/// agent's store dir. A daemon restart resumes from the persisted value, so a
/// message delivered while the daemon was down (its ts is newer than the last
/// processed one) is dispatched on the post-restart initial sync instead of
/// being silently skipped by a fresh "now" seed.
///
/// Persistence is best-effort: a write failure is logged and the in-memory
/// value still dedupes the running process; only resume-after-restart degrades
/// (back to the old seed-to-"now" behavior).
struct Watermark {
    value: AtomicU64,
    path: PathBuf,
}

impl Watermark {
    /// File name inside the store dir, next to the matrix-sdk SQLite stores.
    const FILE_NAME: &'static str = "inbound-watermark";

    /// Load the persisted watermark from `store_dir`, falling back to "now"
    /// (and seeding the file) when it is absent or unparsable. The fallback
    /// preserves the original ignore-pre-startup-backlog behavior exactly
    /// once: the first start with persistence enabled.
    fn load_or_seed(store_dir: &Path) -> Self {
        let path = store_dir.join(Self::FILE_NAME);
        let value = match Self::load(&path) {
            Some(ts) => {
                tracing::info!("inbound watermark restored: {ts} (from {})", path.display());
                ts
            }
            None => {
                let now = now_epoch_ms();
                tracing::info!(
                    "no usable inbound watermark at {}; seeding to now ({now})",
                    path.display()
                );
                Self::persist(&path, now);
                now
            }
        };
        Self {
            value: AtomicU64::new(value),
            path,
        }
    }

    fn load(path: &Path) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Atomic best-effort write: temp file + rename in the same directory, so
    /// a crash mid-write can never leave a torn file (worst case the old value
    /// survives). Failure is a WARN, never fatal.
    fn persist(path: &Path, value: u64) {
        let tmp = path.with_extension("tmp");
        let res = std::fs::write(&tmp, format!("{value}\n"))
            .and_then(|()| std::fs::rename(&tmp, path));
        if let Err(e) = res {
            tracing::warn!(
                "failed to persist inbound watermark to {}: {e:#}",
                path.display()
            );
        }
    }

    /// Current watermark (epoch ms).
    fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Advance to `ts_ms` if it is newer, mirroring the result to disk. The
    /// persisted value is re-read from the atomic AFTER the update so a slower
    /// concurrent advancer tends to write the freshest value; the residual
    /// write race (stale value persisted last) is accepted — its worst case is
    /// one already-handled message re-dispatched after a restart, never a lost
    /// message.
    fn advance(&self, ts_ms: u64) {
        let advanced = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (ts_ms > v).then_some(ts_ms)
            })
            .is_ok();
        if advanced {
            Self::persist(&self.path, self.get());
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::{is_case_only_mismatch, mxid_authorized, validate_target};

    // The real fleet's two contrasting peers: one all-lowercase localpart, one
    // mixed-case `did:key`. Synapse delivers `ev.sender` lowercased in both
    // cases (verified against the live state stores), so authorization must
    // accept the lowercased sender against EITHER configured form.
    const TARGET_LOWER: &str =
        "@did-key-zdnaezp2zvct2tp3zvjkqxynzyzbxnuuz3zw5mhf6cysgyfio:matrix.inblock.io";
    const TARGET_MIXED: &str =
        "@did-key-zDnaef1WiYi9AXZgz55kptPRnTUkt3iZ7U6bqkjmoDMkpvdSL:matrix.inblock.io";

    #[test]
    fn lowercase_sender_matches_lowercase_target() {
        // Trivial exact match: the all-lowercase peer.
        assert!(mxid_authorized(TARGET_LOWER, TARGET_LOWER));
    }

    #[test]
    fn synapse_lowercased_sender_matches_mixed_case_target() {
        // The crux of the bug report: Synapse delivers the mixed-case did:key
        // peer's MXID lowercased. A case-SENSITIVE compare would drop it; the
        // canonical compare must accept it.
        let delivered = TARGET_MIXED.to_ascii_lowercase();
        assert_ne!(delivered, TARGET_MIXED, "fixture must actually differ in case");
        assert!(
            mxid_authorized(&delivered, TARGET_MIXED),
            "lowercased sender must authorize against a mixed-case did:key target"
        );
    }

    #[test]
    fn distinct_peer_is_rejected() {
        // The core security property: a different peer must NOT be authorized.
        assert!(!mxid_authorized(TARGET_LOWER, TARGET_MIXED));
        assert!(!mxid_authorized(
            "@did-key-zeviltwin:matrix.inblock.io",
            TARGET_MIXED
        ));
        // Same localpart, different homeserver — a distinct MXID, must reject.
        assert!(!mxid_authorized(
            "@did-key-zdnaef1wiyi9axzgz55kptprntukt3iz7u6bqkjmodmkpvdsl:evil.example.com",
            TARGET_MIXED
        ));
    }

    #[test]
    fn fold_is_ascii_only_no_unicode_conflation() {
        // We must fold ASCII case ONLY. A non-ASCII codepoint that a Unicode
        // fold might equate to an ASCII letter must NOT match — Synapse keeps
        // such codepoints distinct, so widening here would be a real hole.
        // 'İ' (U+0130) Unicode-lowercases toward 'i'; ASCII fold leaves it alone.
        assert!(!mxid_authorized("@\u{0130}:matrix.inblock.io", "@i:matrix.inblock.io"));
    }

    #[test]
    fn near_miss_is_flagged() {
        // A case-only near-miss: same up to ASCII case but not byte-identical.
        // This is exactly the situation that used to be a SILENT drop under a
        // case-sensitive compare; `is_case_only_mismatch` is what lets the relay
        // surface it as a WARN.
        let delivered = TARGET_MIXED.to_ascii_lowercase();
        assert!(is_case_only_mismatch(&delivered, TARGET_MIXED));
        // An exact match is NOT a near-miss (nothing to warn about).
        assert!(!is_case_only_mismatch(TARGET_LOWER, TARGET_LOWER));
        // A genuinely different sender is NOT a near-miss either.
        assert!(!is_case_only_mismatch(TARGET_LOWER, TARGET_MIXED));
    }

    #[test]
    fn validate_target_accepts_well_formed() {
        assert!(validate_target(TARGET_LOWER, "test"));
        // Mixed-case is still "well-formed" (it only logs an advisory WARN).
        assert!(validate_target(TARGET_MIXED, "test"));
    }

    #[test]
    fn validate_target_rejects_malformed() {
        assert!(!validate_target("not-an-mxid", "test"));
        assert!(!validate_target("@no-server-part", "test"));
        assert!(!validate_target("missing-at:matrix.inblock.io", "test"));
        assert!(!validate_target("@:matrix.inblock.io", "test")); // empty localpart
        assert!(!validate_target("@user:", "test")); // empty server
    }
}

#[cfg(test)]
mod watermark_tests {
    use super::{now_epoch_ms, Watermark};
    use std::path::PathBuf;

    /// Fresh per-test store dir under the OS temp dir (no tempfile dep: the
    /// crate has none, and pid + counter is unique enough for `cargo test`).
    fn temp_store(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aqua-relay-wm-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn absent_file_falls_back_to_now_and_seeds() {
        let dir = temp_store("absent");
        let before = now_epoch_ms();
        let wm = Watermark::load_or_seed(&dir);
        let after = now_epoch_ms();
        // Seeded to "now" (old behavior preserved on first run)...
        assert!(wm.get() >= before && wm.get() <= after);
        // ...and the seed is already on disk, so an immediate restart resumes
        // from it instead of re-seeding.
        assert_eq!(Watermark::load(&dir.join(Watermark::FILE_NAME)), Some(wm.get()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unparsable_file_falls_back_to_now() {
        let dir = temp_store("garbage");
        let path = dir.join(Watermark::FILE_NAME);
        std::fs::write(&path, "not-a-timestamp\n").unwrap();
        let before = now_epoch_ms();
        let wm = Watermark::load_or_seed(&dir);
        assert!(wm.get() >= before, "garbage must fall back to now");
        // The garbage was replaced by the fresh seed.
        assert_eq!(Watermark::load(&path), Some(wm.get()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn advance_persists_and_reloads_across_restart() {
        let dir = temp_store("roundtrip");
        let wm = Watermark::load_or_seed(&dir);
        let ts = wm.get() + 60_000;
        wm.advance(ts);
        assert_eq!(wm.get(), ts);
        // A "restarted daemon" (fresh load from the same store dir) resumes
        // from the persisted value, not from "now".
        let reloaded = Watermark::load_or_seed(&dir);
        assert_eq!(reloaded.get(), ts);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn advance_is_monotonic_in_memory_and_on_disk() {
        let dir = temp_store("monotonic");
        let path = dir.join(Watermark::FILE_NAME);
        let wm = Watermark::load_or_seed(&dir);
        let newer = wm.get() + 1_000;
        wm.advance(newer);
        // An older (or equal) timestamp must neither regress memory nor disk.
        wm.advance(newer - 500);
        wm.advance(newer);
        assert_eq!(wm.get(), newer);
        assert_eq!(Watermark::load(&path), Some(newer));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_handles_trailing_whitespace() {
        let dir = temp_store("trim");
        let path = dir.join(Watermark::FILE_NAME);
        std::fs::write(&path, "1749740000000\n").unwrap();
        assert_eq!(Watermark::load(&path), Some(1_749_740_000_000));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
