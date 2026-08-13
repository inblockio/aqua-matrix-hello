// matrix-sdk 0.17's deeply-nested async types overflow rustc's default
// Send-bound recursion budget when a downstream crate spawns `client.sync(...)`
// in a tokio task (the daemon lifecycle now lives in `aqua-matrix-relay`, but
// the bound is hit through this crate's public API so the limit stays here).
#![recursion_limit = "256"]

mod call;
mod durable;
mod media;
mod recovery;
mod registry;
mod rtc_keys;

pub use durable::{WorkItem, WorkJournal, WorkState};
pub use media::{MediaHandle, MediaKind};
pub use rtc_keys::{
    build_call_encryption_keys_content, element_call_accepts_encryption_keys, CallEncryptionKeys,
    CallEncryptionKeysEventContent, CallKey, CALL_ENCRYPTION_KEYS_TYPE,
};

use anyhow::{anyhow, Context, Result};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use matrix_sdk::{
    config::SyncSettings,
    room::MessagesOptions,
    ruma::{
        events::{
            direct::{DirectEventContent, OwnedDirectUserIdentifier},
            room::member::MembershipState,
            room::message::{MessageType, ReplacementMetadata, RoomMessageEventContent},
            AnySyncMessageLikeEvent, AnySyncTimelineEvent,
        },
        OwnedDeviceId, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UInt, UserId,
    },
    Client, SessionMeta, SessionTokens,
};
use serde::{Deserialize, Serialize};
use siwx_oidc_auth::SiwxKey;
use std::path::{Path, PathBuf};
use mime::Mime;

// ---------------------------------------------------------------------------
// Config file (persisted OIDC credentials)
// ---------------------------------------------------------------------------

const DEFAULT_REDIRECT_URI: &str = "http://localhost:0/callback";
const DEFAULT_CLIENT_NAME: &str = "aqua-matrix-agent";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub oidc: OidcConfig,
    /// Cached Matrix session. Lets restarts within the token's lifetime reuse
    /// the same `device_id` so the SQLite crypto store stays valid.
    /// See docs/ARCHITECTURE.md "Identity and device-id persistence".
    #[serde(default)]
    pub session: Option<SessionCache>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OidcConfig {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCache {
    pub access_token: String,
    pub user_id: String,
    pub device_id: String,
    /// Unix seconds when the access token expires. We refresh ~30s early.
    pub expires_at_unix: u64,
    /// Refresh token from siwx-oidc (24h TTL on standalone). When the
    /// access token has expired we exchange this for a new access token,
    /// preserving the device_id and crypto store.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Persisted DID — needed for the refresh-grant call.
    #[serde(default)]
    pub did: Option<String>,
}

impl ConfigFile {
    /// Load config from a TOML file. Returns default if file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        toml::from_str(&contents)
            .with_context(|| format!("failed to parse config: {}", path.display()))
    }

    /// Save config to a TOML file, creating parent directories if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create config dir: {}", parent.display()))?;
        }
        let contents = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(path, contents)
            .with_context(|| format!("failed to write config: {}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// OIDC dynamic client registration
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterResponse {
    client_id: String,
}

/// Register a new OIDC client with the siwx-oidc server via dynamic registration.
/// Returns (client_id, redirect_uri).
pub async fn register_oidc_client(siwx_url: &str) -> Result<(String, String)> {
    let redirect_uri = DEFAULT_REDIRECT_URI.to_string();
    let url = format!("{}/register", siwx_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "redirect_uris": [&redirect_uri],
        "client_name": DEFAULT_CLIENT_NAME,
        "token_endpoint_auth_method": "none"
    });

    tracing::info!("registering OIDC client at {url}");
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("OIDC client registration request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("OIDC registration returned {status}: {body}");
    }

    let reg: RegisterResponse = resp
        .json()
        .await
        .context("failed to parse OIDC registration response")?;

    tracing::info!("registered OIDC client: {}", reg.client_id);
    Ok((reg.client_id, redirect_uri))
}

// ---------------------------------------------------------------------------
// Agent config and resolution
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AgentConfig {
    pub key_file: PathBuf,
    pub siwx_url: String,
    pub matrix_url: String,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub store_dir: PathBuf,
    /// Optional explicit Matrix `device_id` to pin (e.g. a role-named device
    /// like `heartbeat`, set via `AGENT_DEVICE_ID`). When `None`, `connect`
    /// derives a deterministic, stable id from the agent's DID via
    /// [`stable_device_id`], so existing deployments get device stability with
    /// zero new config. Either way the resolved id is passed to siwx-oidc on
    /// every login, so the agent reuses ONE stable Synapse device instead of
    /// minting a fresh `SIWX_<uuid>` each time. See
    /// docs/ARCHITECTURE.md "Identity and device-id persistence".
    pub device_id: Option<String>,
}

pub struct Message {
    pub sender: String,
    pub body: String,
    pub timestamp_ms: u64,
    pub event_id: String,
}

#[derive(Clone)]
pub struct AgentClient {
    client: Client,
    did: String,
    user_id: OwnedUserId,
    /// Unix seconds when the current access token expires. Used by the daemon
    /// outer-loop to proactively rotate the matrix-sdk Client (which has no
    /// public API to swap tokens in place) ~30 s before the server starts
    /// returning M_UNKNOWN_TOKEN.
    expires_at_unix: u64,
    /// The config this client was built from. Retained so a one-shot send can
    /// self-heal: when the access token is near/at expiry (or the server
    /// returns M_UNKNOWN_TOKEN mid-operation) we re-mint a session from the
    /// persisted refresh token / the did:key and rebuild the inner client in
    /// place. matrix-sdk 0.17 cannot refresh siwx-oidc tokens itself (its
    /// MatrixSession refresh hits Synapse's native endpoint, not siwx-oidc's
    /// `/token`), so the rotation has to happen at this layer.
    config: AgentConfig,
    /// Durable work-journal for the delivery+inbox promise, injected by the relay
    /// (`run_daemon`) so a handler running on a *clone* of this client can record
    /// its answer/error durably ([`record_reply`](Self::record_reply)) and mark it
    /// delivered ([`mark_delivered`](Self::mark_delivered)). `None` for one-shot
    /// CLI use, where there is no daemon lifecycle to redeliver.
    journal: Option<std::sync::Arc<WorkJournal>>,
    /// Signalled by a handler ([`request_recycle`](Self::request_recycle)) when a
    /// live delivery failed, so `run_daemon` ends the current cycle and reconnects
    /// with a fresh token to redeliver the journalled reply within seconds rather
    /// than waiting for the next scheduled cycle.
    recycle: Option<std::sync::Arc<tokio::sync::Notify>>,
}

impl AgentClient {
    /// Expose the underlying matrix-sdk Client (cheaply cloneable, internally Arc'd)
    /// so the heartbeat and claude-channel modes can register event handlers and
    /// drive `client.sync(...)` directly.
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Inject the durable work-journal and recycle signal (called once per cycle by
    /// the relay, before the client is cloned into handlers). After this, a handler
    /// holding a clone can durably record and complete its replies.
    pub fn attach_durability(
        &mut self,
        journal: std::sync::Arc<WorkJournal>,
        recycle: std::sync::Arc<tokio::sync::Notify>,
    ) {
        self.journal = Some(journal);
        self.recycle = Some(recycle);
    }

    /// Whether a durable journal is attached (daemon mode). Handlers use this to
    /// decide between the durable promise path and a plain one-shot send.
    pub fn has_journal(&self) -> bool {
        self.journal.is_some()
    }

    /// Durably record the answer/error for the inbound message `event_id` so it is
    /// guaranteed to be delivered (redelivered by the relay across restarts/token
    /// rotation) even if the live send below fails. No-op without a journal.
    pub fn record_reply(&self, event_id: &str, text: &str) {
        if let Some(j) = &self.journal {
            j.set_to_deliver(event_id, text);
        }
    }

    /// Mark the inbound message `event_id` fully handled — its answer/error has been
    /// confirmed delivered. Removes it from the durable inbox. No-op without a journal.
    pub fn mark_delivered(&self, event_id: &str) {
        if let Some(j) = &self.journal {
            j.mark_done(event_id);
        }
    }

    /// Ask `run_daemon` to end the current cycle and reconnect now (fresh token), so
    /// a journalled-but-undelivered reply is redelivered within seconds. No-op if no
    /// recycle signal is attached.
    pub fn request_recycle(&self) {
        if let Some(r) = &self.recycle {
            r.notify_one();
        }
    }
}

/// Detect a Matrix-acceptable image mime from the file's magic bytes. Keyed on
/// content rather than extension so the uploaded `content_type` always matches
/// the actual bytes — the deploy pipeline mounts the image at a fixed
/// `/agent/avatar.png` path regardless of its real format, so an
/// extension-based guess would be wrong. Dependency-free.
fn avatar_mime(data: &[u8]) -> Result<Mime> {
    let kind = if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if data.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        "image/png"
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        "image/gif"
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        "image/webp"
    } else {
        return Err(anyhow!(
            "unrecognized avatar image format (expected jpeg/png/gif/webp by content)"
        ));
    };
    kind.parse::<Mime>()
        .map_err(|e| anyhow!("failed to parse mime {kind:?}: {e}"))
}

/// Dependency-free content fingerprint for avatar change-detection. This is NOT
/// a cryptographic hash and is not a security boundary — it only decides whether
/// the on-disk avatar differs from the one we last uploaded.
fn content_fingerprint(data: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Load configuration from a `.env` file into the process environment, to be
/// called once at the very start of `main` — **before** parsing args — so that
/// `clap`'s `env`-backed flags (`AGENT_TARGET`, `MATRIX_URL`, `SIWX_URL`, …)
/// pick up file-provided values.
///
/// This is what makes each agent *instance* self-describing: point it at its own
/// file via the `AGENT_ENV_FILE` environment variable (the multi-agent path —
/// every instance gets a distinct `.env`); with `AGENT_ENV_FILE` unset it falls
/// back to a conventional `.env` discovered in the working directory or an
/// ancestor.
///
/// Already-set process variables are **not** overridden (that is `dotenvy`'s
/// default), which yields the precedence: explicit CLI flag > process env (e.g.
/// systemd `Environment=`) > `.env` file > built-in default. Best-effort: a
/// missing file is not an error — real env vars and defaults still apply.
pub fn load_dotenv() {
    match std::env::var_os("AGENT_ENV_FILE") {
        Some(path) => {
            if let Err(e) = dotenvy::from_path(Path::new(&path)) {
                tracing::warn!("AGENT_ENV_FILE={path:?} could not be loaded: {e}");
            }
        }
        None => {
            // No explicit file: load a conventional `.env` if one exists.
            let _ = dotenvy::dotenv();
        }
    }
}

pub fn did_from_key_file(path: &Path) -> Result<String> {
    if path.exists() {
        let key = SiwxKey::from_pem_file(path).context("failed to load key")?;
        Ok(key.did())
    } else {
        let key = SiwxKey::generate_ed25519();
        std::fs::write(path, key.to_pem()?).context("failed to write key")?;
        Ok(key.did())
    }
}

/// Derive a deterministic, stable Synapse `device_id` from an agent's DID.
///
/// Scheme: `AQUA_` + the first 12 lowercase-hex characters of `SHA-256(did)`.
/// This is the zero-config default device id used whenever an operator has not
/// pinned an explicit [`AgentConfig::device_id`] / `AGENT_DEVICE_ID`. Because it
/// is a pure function of the DID, the same agent re-derives the SAME device on
/// every login and restart, so siwx-oidc's idempotent device upsert reuses one
/// stable Synapse device instead of minting a fresh `SIWX_<uuid>` each time.
///
/// Properties (see the unit tests): deterministic (same DID -> same id),
/// distinct (different DIDs almost never collide -- 48 bits of digest), and a
/// valid device_id (compact ASCII, no whitespace, well under Synapse's length
/// limit). 12 hex chars is short enough to stay readable in logs yet wide
/// enough that a collision across a realistic fleet is negligible.
pub fn stable_device_id(did: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(did.as_bytes());
    let hex = hex::encode(digest); // lowercase hex, 64 chars
    format!("AQUA_{}", &hex[..12])
}

/// Resolve the effective stable device_id: the explicit value (trimmed) when
/// given and non-empty, else the id derived from the DID.
///
/// A blank explicit value (e.g. `AGENT_DEVICE_ID=`) is treated as unset so a
/// misconfiguration falls back to the derived id rather than pinning an empty
/// device scope. An explicit id with INTERNAL whitespace is rejected outright:
/// the device_id rides in the OAuth `scope` parameter, which is
/// whitespace-delimited, so the server would silently truncate `"my device"`
/// to `"my"` and the cache-divergence guard would then discard the session
/// cache on every connect. Failing loudly here surfaces the config bug at
/// startup instead.
fn resolve_effective_device_id(explicit: Option<&str>, did: &str) -> Result<String> {
    match explicit.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) if s.chars().any(char::is_whitespace) => Err(anyhow!(
            "explicit device_id {s:?} contains whitespace; device_id is carried in the \
             whitespace-delimited OAuth scope and would be silently truncated by the server"
        )),
        Some(s) => Ok(s.to_owned()),
        None => Ok(stable_device_id(did)),
    }
}

#[derive(Deserialize)]
struct WhoAmI {
    user_id: String,
    device_id: String,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_store_mismatch(err: &anyhow::Error) -> bool {
    // matrix-sdk wraps this from the crypto store. The string is the load-bearing
    // signal — there is no typed error variant exposed at this layer.
    let chain: String = err.chain().map(|e| e.to_string()).collect::<Vec<_>>().join(" | ");
    chain.contains("account in the store doesn't match")
        || chain.contains("crypto store the account in the store")
}

// TODO(aqua-security): seal/audit
/// Extract Megolm `session_id` from encrypted timeline JSON, if present.
/// Used by the UTD recovery path in [`AgentClient::messages`] so we can target a
/// single-session key-backup download instead of always pulling the whole room.
///
/// Pure JSON helper so unit tests can lock the recovery contract without a live
/// `TimelineEvent`.
pub(crate) fn megolm_session_id_from_json(raw_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw_json).ok()?;
    value
        .get("content")
        .and_then(|c| c.get("session_id"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_owned())
}

fn megolm_session_id_from_raw(
    raw: &matrix_sdk::ruma::serde::Raw<AnySyncTimelineEvent>,
) -> Option<String> {
    megolm_session_id_from_json(raw.json().get())
}

fn wipe_crypto_store(store_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(store_dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("matrix-sdk-") && name.contains(".sqlite3") {
            let path = entry.path();
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("failed to remove {}: {e}", path.display());
            } else {
                tracing::info!("wiped {}", path.display());
            }
        }
    }
}

async fn build_and_restore(
    matrix_url: &str,
    store_dir: &Path,
    user_id: &OwnedUserId,
    device_id: &OwnedDeviceId,
    access_token: &str,
) -> Result<Client> {
    let client = Client::builder()
        .homeserver_url(matrix_url)
        .sqlite_store(store_dir, None)
        .build()
        .await
        .context("failed to build Matrix client")?;

    let session = matrix_sdk::authentication::matrix::MatrixSession {
        meta: SessionMeta {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
        },
        tokens: SessionTokens {
            access_token: access_token.to_string(),
            refresh_token: None,
        },
    };
    client
        .matrix_auth()
        .restore_session(session, matrix_sdk::store::RoomLoadSettings::default())
        .await
        .context("failed to restore session")?;
    Ok(client)
}

async fn resolve_identity(matrix_url: &str, access_token: &str) -> Result<WhoAmI> {
    let url = format!("{matrix_url}/_matrix/client/v3/account/whoami");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .context("whoami request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("whoami returned {status}: {body}");
    }
    resp.json().await.context("whoami JSON parse failed")
}

/// Resolve the OIDC `(client_id, redirect_uri)` to use, in this order:
///   1. Provided in `config` (CLI flags or env vars)
///   2. Cached in the on-disk config file
///   3. Auto-register a fresh client with the siwx-oidc server
///
/// May mutate `config_file` (and persist it) when it auto-registers. Pulled out
/// of `connect()` so the self-healing re-auth path resolves the same way.
async fn resolve_oidc_client(
    config: &AgentConfig,
    config_file: &mut ConfigFile,
    config_path: &Path,
) -> Result<(String, String)> {
    match (config.client_id.clone(), config.redirect_uri.clone()) {
        (Some(cid), Some(ruri)) => Ok((cid, ruri)),
        (Some(cid), None) => {
            let ruri = config_file
                .oidc
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string());
            Ok((cid, ruri))
        }
        (None, Some(ruri)) => {
            let cid = config_file.oidc.client_id.clone().ok_or_else(|| {
                anyhow!("--redirect-uri provided without --client-id, and no cached client_id found")
            })?;
            Ok((cid, ruri))
        }
        (None, None) => {
            if let Some(cid) = config_file.oidc.client_id.clone() {
                let ruri = config_file
                    .oidc
                    .redirect_uri
                    .clone()
                    .unwrap_or_else(|| DEFAULT_REDIRECT_URI.to_string());
                tracing::info!("using cached OIDC credentials from {}", config_path.display());
                Ok((cid, ruri))
            } else {
                let (cid, ruri) = register_oidc_client(&config.siwx_url).await?;
                config_file.oidc.client_id = Some(cid.clone());
                config_file.oidc.redirect_uri = Some(ruri.clone());
                config_file.save(config_path)?;
                tracing::info!("saved OIDC credentials to {}", config_path.display());
                Ok((cid, ruri))
            }
        }
    }
}

/// Acquire a usable Matrix session, persisting it to `config.toml`. Preference:
///   1. Cached access token still within its TTL  → use it (no network).
///   2. Cached refresh token → exchange for a new access token via
///      `siwx_oidc_auth::refresh()` (preserves device_id → crypto store stays valid).
///   3. Fresh `did:key` authentication → pins the stable `effective_device_id`
///      (explicit `AGENT_DEVICE_ID` or derived from the DID via
///      [`stable_device_id`]), so the agent reuses ONE Synapse device instead of
///      minting a fresh `SIWX_<uuid>` each time.
///
/// A cached session whose `device_id` does not match the effective id is
/// discarded up front (the `SIWX_` → `AQUA_` migration guard, see below), so
/// every tier converges on the stable device.
///
/// Returns `(access_token, user_id, device_id, expires_at_unix)`. This is the
/// single source of truth for "give me a live token", shared by the initial
/// `connect()` and the on-401 / near-expiry self-heal in `reauth_inner()` —
/// which therefore pin the stable device_id identically.
/// `force_new` skips the still-valid-cache shortcut so a session that is
/// near-expiry (but not yet rejected) is rotated rather than reused.
async fn acquire_session(
    config: &AgentConfig,
    key: &SiwxKey,
    client_id: &str,
    redirect_uri: &str,
    config_file: &mut ConfigFile,
    config_path: &Path,
    force_new: bool,
) -> Result<(String, String, String, u64)> {
    // Resolve the EFFECTIVE stable device_id, pinned on every fresh auth so the
    // agent reuses ONE Synapse device instead of minting a fresh `SIWX_<uuid>`
    // each time. Precedence:
    //   (a) explicit `config.device_id` / `AGENT_DEVICE_ID` (ops can name a
    //       role device like `heartbeat`);
    //   (b) otherwise a deterministic id derived from the DID
    //       (`stable_device_id`), so existing deployments get stability with
    //       zero new config.
    // See `resolve_effective_device_id` for the blank/whitespace handling and
    // docs/ARCHITECTURE.md "Identity and device-id persistence".
    let effective_device_id =
        resolve_effective_device_id(config.device_id.as_deref(), &key.did())?;
    tracing::info!("effective device_id: {effective_device_id}");

    let now_unix = unix_now();
    // SIWX_ → AQUA_ TRANSITION (cache divergence guard): a session cached before
    // stable device_ids existed holds an old `SIWX_<uuid>`, while we now pin
    // `AQUA_…` (or an explicit AGENT_DEVICE_ID). Reusing/refreshing such a cache
    // would keep the agent on the OLD device for up to the refresh-token TTL
    // (~24h). So we only honour the cache when its `device_id` already matches
    // the effective id; otherwise we discard it and fall through to a fresh auth
    // that provisions the stable device. The store, still bound to the old
    // device, then fails `restore_session` with "account in the store doesn't
    // match", and the caller's wipe-and-retry rebuilds it for the new device
    // (a one-time fresh provision + crypto-store reset, cross-signing
    // re-bootstraps). This makes the transition deterministic and converge on
    // the first login, not eventually. The same guard handles an operator
    // changing AGENT_DEVICE_ID.
    let cached_clone = config_file.session.clone().filter(|sess| {
        if sess.device_id == effective_device_id {
            true
        } else {
            tracing::warn!(
                "cached session device_id {} != effective {}; discarding cache to converge on the stable device",
                sess.device_id,
                effective_device_id
            );
            false
        }
    });

    let session_data: Option<(String, String, String, u64)> = if let Some(sess) = cached_clone {
        if !force_new && sess.expires_at_unix > now_unix + 30 {
            tracing::info!(
                "cached access token still valid ({}s left, device_id: {})",
                sess.expires_at_unix.saturating_sub(now_unix),
                sess.device_id
            );
            match resolve_identity(&config.matrix_url, &sess.access_token).await {
                Ok(id) if id.user_id == sess.user_id && id.device_id == sess.device_id => {
                    tracing::info!("cached session validated; skipping auth");
                    Some((sess.access_token, sess.user_id, sess.device_id, sess.expires_at_unix))
                }
                Ok(_) => {
                    tracing::warn!("cached session whoami returned different identity; falling through");
                    None
                }
                Err(e) => {
                    tracing::warn!("cached session whoami failed: {e:#}; falling through");
                    None
                }
            }
        } else if let (Some(rt), Some(saved_did)) = (sess.refresh_token.as_ref(), sess.did.as_ref()) {
            tracing::info!(
                "{}; attempting refresh grant (device_id: {})",
                if force_new { "forcing token rotation" } else { "access token expired" },
                sess.device_id
            );
            match siwx_oidc_auth::refresh(&config.siwx_url, client_id, rt, saved_did).await {
                Ok(new_tokens) => {
                    let expires_in = new_tokens.expires_in.unwrap_or(300);
                    tracing::info!(
                        "refresh grant succeeded (new access token expires in {}s, device_id preserved)",
                        expires_in
                    );
                    let refreshed = SessionCache {
                        access_token: new_tokens.access_token.clone(),
                        user_id: sess.user_id.clone(),
                        device_id: sess.device_id.clone(),
                        expires_at_unix: unix_now().saturating_add(expires_in),
                        // If the server rotated the refresh token, persist the new one;
                        // otherwise keep the old one (siwx-oidc may or may not rotate).
                        refresh_token: new_tokens.refresh_token.or_else(|| Some(rt.clone())),
                        did: Some(saved_did.clone()),
                    };
                    config_file.session = Some(refreshed.clone());
                    if let Err(e) = config_file.save(config_path) {
                        tracing::warn!("failed to persist refreshed session: {e:#}");
                    }
                    Some((refreshed.access_token, refreshed.user_id, refreshed.device_id, refreshed.expires_at_unix))
                }
                Err(e) => {
                    tracing::warn!("refresh grant failed: {e:#}; falling through to fresh auth");
                    None
                }
            }
        } else {
            tracing::info!("cached access token expired and no refresh_token; re-authenticating");
            None
        }
    } else {
        None
    };

    if let Some(quad) = session_data {
        return Ok(quad);
    }

    tracing::info!(
        "authenticating against {} (pinning device_id {})",
        config.siwx_url,
        effective_device_id
    );
    // Pin the stable device_id so siwx-oidc provisions (idempotent upsert,
    // never deletes) that exact Synapse device instead of minting a fresh
    // `SIWX_<uuid>`. Re-provisioning the same id preserves the device's E2EE
    // keys, so the agent keeps one stable device across every login.
    let tokens = siwx_oidc_auth::authenticate_with_device(
        &config.siwx_url,
        client_id,
        redirect_uri,
        key,
        Some(&effective_device_id),
    )
    .await
    .context("siwx-oidc authentication failed")?;
    let expires_in = tokens.expires_in.unwrap_or(300);
    tracing::info!(
        "access token acquired (expires in {}s, refresh_token: {})",
        expires_in,
        if tokens.refresh_token.is_some() { "yes" } else { "no" }
    );

    let identity = resolve_identity(&config.matrix_url, &tokens.access_token).await?;
    tracing::info!("matrix user: {}, device: {}", identity.user_id, identity.device_id);
    // The deployed siwx-oidc honours the proposed device scope verbatim. If a
    // server ever ignores it, the divergence guard above would discard the
    // cache on EVERY connect (perpetual full OAuth, store wipes on reauth).
    // Diagnose that server-side defect at auth time, not as a guard warn later.
    if identity.device_id != effective_device_id {
        tracing::error!(
            "server provisioned device_id {} instead of the requested {}; the session cache \
             will be discarded on the next connect. Check that the siwx-oidc version honours \
             the device scope.",
            identity.device_id,
            effective_device_id
        );
    }

    let expires_at_unix = unix_now().saturating_add(expires_in);
    config_file.session = Some(SessionCache {
        access_token: tokens.access_token.clone(),
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        expires_at_unix,
        refresh_token: tokens.refresh_token,
        did: Some(tokens.did.clone()),
    });
    if let Err(e) = config_file.save(config_path) {
        tracing::warn!("failed to persist session cache: {e:#} (continuing anyway)");
    }
    Ok((tokens.access_token, identity.user_id, identity.device_id, expires_at_unix))
}

/// True if `err`'s chain carries a Matrix `M_UNKNOWN_TOKEN` (the access token
/// was rejected — expired or revoked). String-matched because `send_dm` wraps
/// the typed matrix-sdk error in `anyhow` (same approach as `is_store_mismatch`).
///
/// `pub` so backend crates (e.g. `aqua-matrix-claude-p`, re-exported via
/// `aqua-matrix-relay`) can classify a `ReplyStream::finish` failure the same
/// way the `*_with_refresh` wrappers below do, instead of redefining this
/// string match a second time.
pub fn is_unknown_token(err: &anyhow::Error) -> bool {
    let chain: String = err.chain().map(|e| e.to_string()).collect::<Vec<_>>().join(" | ");
    chain.contains("M_UNKNOWN_TOKEN")
        || chain.contains("UnknownToken")
        || chain.contains("Token is not active")
}

/// True if `err` is a homeserver-side `5xx` / `M_UNKNOWN Internal server error`.
/// Such a failure is NOT something a client retry or a token rotation can fix —
/// the send path is broken server-side (observed live: Synapse 1.153.0 returning
/// 500 on every `m.room.message`/`m.room.encrypted` PUT while reads, room
/// creation, ephemeral and *state* writes all succeed). We bail fast on this so
/// a notify call returns in seconds instead of burning ~5 min of token life per
/// attempt inside matrix-sdk's internal 5xx retry loop.
fn is_server_internal_error(err: &anyhow::Error) -> bool {
    let chain: String = err.chain().map(|e| e.to_string()).collect::<Vec<_>>().join(" | ");
    // `M_UNKNOWN` is Matrix's generic errcode for a 5xx, but `M_UNKNOWN_TOKEN` (an
    // access-token rejection, recovered by `is_unknown_token` + the reactive re-auth in
    // `send_dm_self_healing`) ALSO contains the substring "M_UNKNOWN". Exclude it, else a
    // dead/rotated token is misclassified as an unrecoverable server fault and the re-auth
    // arm becomes dead code (the matched arm order checks server-error first).
    (chain.contains("M_UNKNOWN") && !chain.contains("M_UNKNOWN_TOKEN"))
        || chain.contains("status_code: 500")
        || chain.contains("Internal server error")
}

/// Hard cap on a single `room.send`. matrix-sdk retries a 5xx internally with
/// backoff for several minutes — long enough to outlive a 300s access token (the
/// mechanism that turned a server 500 into the observed `M_UNKNOWN_TOKEN`). This
/// timeout makes a wedged send return promptly so the self-heal logic, not the
/// token clock, decides what happens next.
const SEND_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// Pure classification used by [`AgentClient::reconcile_owner_dms`]: given the
/// owner's recorded DM rooms (in `m.direct` order, possibly with duplicates) and a
/// predicate reporting whether a room is positively STALE (the owner has Left /
/// been banned), return `(kept, dropped)` — both deduped, first-seen order
/// preserved. Conservative by design: only positively-stale rooms are dropped, so
/// a transient sync gap ("member unknown") never evicts a live DM.
fn partition_dm_rooms(
    original: &[OwnedRoomId],
    is_stale: &dyn Fn(&OwnedRoomId) -> bool,
) -> (Vec<OwnedRoomId>, Vec<OwnedRoomId>) {
    let mut seen = std::collections::HashSet::new();
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for r in original {
        if !seen.insert(r.clone()) {
            continue; // duplicate
        }
        if is_stale(r) {
            dropped.push(r.clone());
        } else {
            kept.push(r.clone());
        }
    }
    (kept, dropped)
}

/// Best-effort: after a store-wipe re-bootstrap minted a NEW device_id, delete the
/// agent's OTHER server-side devices, so peers stop encrypting to dead devices
/// whose Megolm keys this device can never read. Under MSC3861/OIDC delegated auth
/// the Client-Server device-deletion endpoint may be disabled (device lifecycle
/// belongs to the OIDC provider) — in that case we log and move on; the stale
/// devices age out on the server. Never fatal.
async fn prune_stale_devices(client: &Client, keep_device_id: &str) {
    let devices = match client.devices().await {
        Ok(r) => r.devices,
        Err(e) => {
            tracing::warn!("device prune: could not list devices: {e:#}");
            return;
        }
    };
    let stale: Vec<OwnedDeviceId> = devices
        .into_iter()
        .map(|d| d.device_id)
        .filter(|id| id.as_str() != keep_device_id)
        .collect();
    if stale.is_empty() {
        tracing::info!(keep = keep_device_id, "device prune: no stale devices to remove");
        return;
    }
    tracing::info!(
        keep = keep_device_id,
        stale = stale.len(),
        "device prune: deleting stale server-side devices after store-wipe re-bootstrap"
    );
    match client.delete_devices(&stale, None).await {
        Ok(_) => tracing::info!(deleted = stale.len(), "device prune: stale devices deleted"),
        Err(e) => tracing::warn!(
            "device prune: delete_devices failed (OIDC/MSC3861 may disable C-S device deletion; \
             stale devices will age out server-side or need OIDC-provider cleanup): {e:#}"
        ),
    }
}

impl AgentClient {
    /// Resolve THE 1:1 direct room for `target`, deterministically and liveness-checked.
    ///
    /// A DM is only usable if the OTHER party is still present: a room the target
    /// LEFT (or was banned/kicked from) can no longer exchange Megolm keys, so its
    /// events become permanently undecryptable. matrix-sdk's `get_dm_room()` returns
    /// the first `m.direct` match in *undefined order* and never checks the peer's
    /// membership — so a stale/duplicate `m.direct` entry silently bound `#shell` +
    /// delivery to a dead room in the 2026-06-06 transcript-agent incident.
    ///
    /// Instead we scan joined rooms, keep only small (≤2 joined) rooms where the
    /// target's membership is `Join` (or `Invite` — a freshly created DM the peer
    /// hasn't accepted yet), and pick deterministically: prefer `Join` over
    /// `Invite`, then the most-recently-active room, then a stable room-id order.
    async fn find_dm_room(&self, target: &UserId) -> Option<matrix_sdk::Room> {
        // (room, rank): rank 2 = target Join, 1 = target Invite. Leave/Ban/Knock excluded.
        let mut candidates: Vec<(matrix_sdk::Room, u8)> = Vec::new();
        for room in self.client.joined_rooms() {
            if room.joined_members_count() > 2 {
                continue; // group room, not a 1:1 DM
            }
            let Some(member) = room.get_member(target).await.ok().flatten() else {
                continue;
            };
            let rank = match member.membership() {
                MembershipState::Join => 2u8,
                MembershipState::Invite => 1u8,
                _ => continue, // Leave / Ban / Knock → stale, never select
            };
            candidates.push((room, rank));
        }
        match candidates.len() {
            0 => None,
            1 => candidates.into_iter().next().map(|(r, _)| r),
            _ => {
                // Genuine multiple live DMs (rare): break ties by newest activity.
                // Cheap (limit=1) and only on the multi-candidate path.
                let mut scored: Vec<(matrix_sdk::Room, u8, u64)> = Vec::with_capacity(candidates.len());
                for (room, rank) in candidates {
                    let ts = self
                        .messages(room.room_id().as_str(), 1)
                        .await
                        .ok()
                        .and_then(|m| m.iter().map(|x| x.timestamp_ms).max())
                        .unwrap_or(0);
                    scored.push((room, rank, ts));
                }
                scored.sort_by(|a, b| {
                    b.1.cmp(&a.1)
                        .then(b.2.cmp(&a.2))
                        .then(a.0.room_id().cmp(b.0.room_id()))
                });
                scored.into_iter().next().map(|(r, _, _)| r)
            }
        }
    }

    pub async fn connect(config: AgentConfig) -> Result<Self> {
        let key = if config.key_file.exists() {
            tracing::info!("loading key from {}", config.key_file.display());
            SiwxKey::from_pem_file(&config.key_file).context("failed to load key")?
        } else {
            tracing::info!("generating Ed25519 key at {}", config.key_file.display());
            let key = SiwxKey::generate_ed25519();
            std::fs::write(&config.key_file, key.to_pem()?).context("failed to write key")?;
            key
        };
        let did = key.did();
        tracing::info!("agent DID: {did}");

        // Resolve OIDC client + a usable Matrix session (cached token → refresh
        // grant → fresh did:key auth). Both steps live in standalone helpers so
        // the on-401 / near-expiry self-heal (`reauth_inner`) re-mints exactly
        // the same way — including the stable device_id pinning, which lives in
        // `acquire_session`. See docs/ARCHITECTURE.md "Identity and device-id persistence".
        let config_path = config.store_dir.join("config.toml");
        let mut config_file = ConfigFile::load(&config_path).unwrap_or_default();

        let (client_id, redirect_uri) =
            resolve_oidc_client(&config, &mut config_file, &config_path).await?;

        let (access_token, user_id_str, device_id_str, expires_at_unix) = acquire_session(
            &config,
            &key,
            &client_id,
            &redirect_uri,
            &mut config_file,
            &config_path,
            false,
        )
        .await?;

        let user_id: OwnedUserId = user_id_str
            .try_into()
            .map_err(|e| anyhow!("invalid user_id: {e}"))?;
        let device_id: OwnedDeviceId = device_id_str.into();

        std::fs::create_dir_all(&config.store_dir)?;

        // Build client + restore session, with one wipe-and-retry on store mismatch.
        // We now pin a STABLE device_id, so a fresh auth normally returns the
        // SAME device and the existing SQLite crypto store still matches — no
        // wipe. The retry remains for the genuine divergence cases: the one-time
        // SIWX_ → AQUA_ migration (the store is still bound to the old
        // `SIWX_<uuid>`), or an operator changing AGENT_DEVICE_ID. The store
        // binds to the device_id it was created with; when they diverge we wipe
        // matrix-sdk-*.sqlite3* (NOT config.toml) and let cross-signing
        // re-bootstrap on the (new) stable device.
        let mut wiped = false;
        let client = match build_and_restore(
            &config.matrix_url,
            &config.store_dir,
            &user_id,
            &device_id,
            &access_token,
        )
        .await
        {
            Ok(c) => c,
            Err(e) if is_store_mismatch(&e) => {
                tracing::warn!(
                    "crypto store device_id mismatch; wiping store and retrying once: {e:#}"
                );
                wipe_crypto_store(&config.store_dir);
                wiped = true;
                build_and_restore(
                    &config.matrix_url,
                    &config.store_dir,
                    &user_id,
                    &device_id,
                    &access_token,
                )
                .await
                .context("restore_session failed even after store wipe")?
            }
            Err(e) => return Err(e),
        };

        tracing::info!("running initial sync");
        client
            .sync_once(SyncSettings::default())
            .await
            .context("initial sync failed")?;
        // Log device_id on every connect so device CHURN (a fresh did:key auth
        // minting a new device, leaving orphaned server-side devices the peer may
        // still encrypt to) is visible in the journal. See `prune_stale_devices`.
        tracing::info!(device_id = %device_id, store_wiped = wiped, "connected");

        // Cold-start recovery: if a recovery key was persisted and cross-signing
        // is NOT yet complete (e.g. after a store wipe), restore cross-signing +
        // secrets from server-side SSSS BEFORE the bootstrap decision below, so
        // restored keys make the status complete and bootstrap is skipped.
        recovery::restore_if_needed(&client, &config.store_dir).await;

        // Verify device via cross-signing
        tracing::info!("checking cross-signing status");
        match client.encryption().cross_signing_status().await {
            Some(status) if status.is_complete() => {
                tracing::info!(
                    "cross-signing keys already present (master={}, self_signing={}, user_signing={})",
                    status.has_master,
                    status.has_self_signing,
                    status.has_user_signing,
                );
            }
            _ => {
                tracing::info!("bootstrapping cross-signing keys");
                match client
                    .encryption()
                    .bootstrap_cross_signing(None)
                    .await
                {
                    Ok(()) => {
                        tracing::info!("cross-signing bootstrap complete; device is now verified");
                    }
                    Err(e) => {
                        tracing::warn!(
                            "cross-signing bootstrap failed (server may not support it): {e:#}"
                        );
                    }
                }
            }
        }

        // After cross-signing keys exist, enable recovery (creates SSSS +
        // server-side backup) and persist the generated recovery key to disk if
        // it isn't there yet. Best-effort: never fails connect().
        recovery::enable_and_persist_if_absent(&client, &config.store_dir).await;

        // If we just re-bootstrapped onto a NEW device_id (store wipe), the peer's
        // client may still be encrypting to our previous, now-dead devices (whose
        // keys this device can't read → undecryptable messages). Best-effort prune
        // of the stale server-side devices. Only on the wipe path (rare).
        if wiped {
            prune_stale_devices(&client, device_id.as_str()).await;
        }

        Ok(Self {
            client,
            did,
            user_id,
            expires_at_unix,
            config,
            journal: None,
            recycle: None,
        })
    }

    /// Re-mint the Matrix session non-interactively and rebuild the inner
    /// matrix-sdk client in place. Used by the send path to self-heal when the
    /// cached access token has expired or been rejected (`M_UNKNOWN_TOKEN`).
    ///
    /// It reloads the `did:key`, resolves the OIDC client, then calls
    /// [`acquire_session`] with `force_new = true` (so a near-expiry token is
    /// rotated, not reused) — which exchanges the persisted refresh token for a
    /// fresh access token, or, if that fails, re-authenticates from the key.
    /// The device_id is preserved across a refresh grant, so the existing
    /// SQLite crypto store stays valid and no re-bootstrap is needed; a store
    /// mismatch (only possible if a *fresh* auth minted a new device_id) is
    /// handled by the same wipe-and-retry as `connect()`.
    /// Rotate the session. `sync_after = true` runs a fresh `sync_once` so an
    /// immediately-following SEND can resolve the DM room + Megolm session.
    /// `sync_after = false` skips that sync — for a client that ONLY does REST
    /// reads (`messages`) or reads state from the shared store kept fresh by a
    /// DIFFERENT syncing client. Skipping the sync avoids a SECOND concurrent
    /// sync on the same device, which would race to-device (Megolm key) delivery
    /// against the other client and silently drop room keys (H9 single-sync).
    async fn reauth_inner(&mut self, sync_after: bool) -> Result<()> {
        let key = SiwxKey::from_pem_file(&self.config.key_file)
            .context("reauth: failed to load key")?;
        let config_path = self.config.store_dir.join("config.toml");
        let mut config_file = ConfigFile::load(&config_path).unwrap_or_default();
        let (client_id, redirect_uri) =
            resolve_oidc_client(&self.config, &mut config_file, &config_path).await?;

        let (access_token, user_id_str, device_id_str, expires_at_unix) = acquire_session(
            &self.config,
            &key,
            &client_id,
            &redirect_uri,
            &mut config_file,
            &config_path,
            true,
        )
        .await
        .context("reauth: could not acquire a fresh session")?;

        let user_id: OwnedUserId = user_id_str
            .try_into()
            .map_err(|e| anyhow!("reauth: invalid user_id: {e}"))?;
        let device_id: OwnedDeviceId = device_id_str.into();

        let client = match build_and_restore(
            &self.config.matrix_url,
            &self.config.store_dir,
            &user_id,
            &device_id,
            &access_token,
        )
        .await
        {
            Ok(c) => c,
            Err(e) if is_store_mismatch(&e) => {
                tracing::warn!("reauth: crypto store device_id mismatch; wiping and retrying once: {e:#}");
                wipe_crypto_store(&self.config.store_dir);
                build_and_restore(
                    &self.config.matrix_url,
                    &self.config.store_dir,
                    &user_id,
                    &device_id,
                    &access_token,
                )
                .await
                .context("reauth: restore_session failed even after store wipe")?
            }
            Err(e) => return Err(e),
        };

        // A fresh sync primes the new client's room/membership state so the
        // immediately-following send resolves the DM room and Megolm session.
        // Skipped for token-only refreshes (see `sync_after` doc) to avoid a
        // second concurrent sync racing to-device key delivery.
        if sync_after {
            client
                .sync_once(SyncSettings::default())
                .await
                .context("reauth: post-reauth sync failed")?;
        }

        self.client = client;
        self.user_id = user_id;
        self.expires_at_unix = expires_at_unix;
        tracing::info!(
            sync_after,
            "reauth: session rotated; new token valid for {}s",
            expires_at_unix.saturating_sub(unix_now())
        );
        Ok(())
    }

    /// Rotate the access token IN PLACE without a fresh `sync_once`. Use from a
    /// client that only does REST reads (`messages`) or reads state from a store
    /// kept fresh by another syncing client — e.g. the in-call control/presence
    /// poller, which must NOT run a second sync alongside the E2EE media driver on
    /// the same device (that race silently drops Megolm room keys → undecryptable
    /// audio → empty transcripts). See `reauth_inner`'s `sync_after` rationale.
    pub async fn reauth_token_only(&mut self) -> Result<()> {
        self.reauth_inner(false).await
    }

    /// Seconds of life left on the current access token (0 if already expired).
    fn token_seconds_left(&self) -> u64 {
        self.expires_at_unix.saturating_sub(unix_now())
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn user_id(&self) -> &str {
        self.user_id.as_str()
    }

    /// This session's Matrix device id, if the client has one yet. Needed by the
    /// MatrixRTC join flow (the lk-jwt-service keys a LiveKit identity on it).
    pub fn device_id(&self) -> Option<String> {
        self.client.device_id().map(|d| d.to_string())
    }

    pub async fn join_invited_rooms(&self) -> Result<Vec<String>> {
        let mut joined = Vec::new();
        for room in self.client.invited_rooms() {
            let room_id = room.room_id().to_owned();
            match room.join().await {
                Ok(_) => {
                    tracing::info!("joined invited room: {room_id}");
                    joined.push(room_id.to_string());
                }
                Err(e) => {
                    tracing::warn!("failed to join room {room_id}: {e}");
                }
            }
        }
        Ok(joined)
    }

    pub async fn dm_room_id(&self, target: &str) -> Result<Option<String>> {
        let target: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid user_id: {e}"))?;
        Ok(self
            .find_dm_room(target)
            .await
            .map(|r| r.room_id().to_string()))
    }

    /// Record `room_id` as the direct (DM) room for `target` in `m.direct`
    /// account data, so a later `find_dm_room`/`send_dm` resolves it
    /// deterministically — without waiting for a full membership sync. A daemon
    /// that has just *joined* an invite should call this so its first outbound
    /// message (e.g. a hello) reuses the shared room the peer created, instead
    /// of `create_dm` spawning a duplicate room (which splits the two sides into
    /// separate rooms and breaks Megolm key exchange). Best-effort by the caller.
    pub async fn mark_dm(&self, room_id: &str, target: &str) -> Result<()> {
        let room_id: OwnedRoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        let target: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid target: {e}"))?;
        // Dedup-aware: matrix-sdk's `mark_as_dm` appends unconditionally, so over
        // repeated joins/marks it accumulates duplicate `m.direct` entries (which,
        // with the order-undefined `get_dm_room`, bound `#shell`/delivery to a dead
        // room in the 2026-06-06 incident). Only write if not already recorded.
        let raw = self
            .client
            .account()
            .fetch_account_data_static::<DirectEventContent>()
            .await
            .context("fetch m.direct failed")?;
        let mut content = raw
            .map(|r| r.deserialize())
            .transpose()
            .context("deserialize m.direct failed")?
            .unwrap_or_default();
        let key: OwnedDirectUserIdentifier = target.into();
        let list = content.entry(key).or_default();
        if list.iter().any(|r| r == &room_id) {
            return Ok(()); // already marked — no redundant server write
        }
        list.push(room_id);
        self.client
            .account()
            .set_account_data(content)
            .await
            .context("set m.direct failed")?;
        Ok(())
    }

    /// Reconcile `m.direct` for `owner` to the LIVE 1:1 DM(s) only, and leave+forget
    /// any DM rooms the owner has abandoned.
    ///
    /// `mark_as_dm` appends, so repeated joins accumulate duplicate + stale entries;
    /// combined with the order-undefined `get_dm_room`, a stale entry silently bound
    /// `#shell`/delivery to a dead (undecryptable) room in the 2026-06-06 incident.
    /// Run once at startup. Best-effort — a hiccup must never be fatal to the caller.
    ///
    /// "Live" = the agent is currently joined AND the owner's membership is `Join`
    /// or `Invite`. Rooms where the owner has Left/been-banned are dropped from
    /// `m.direct` and (if the agent is still joined) left+forgotten so they stop
    /// generating undecryptable-event churn on every poll.
    pub async fn reconcile_owner_dms(&self, owner: &str) -> Result<()> {
        let owner: &UserId = owner
            .try_into()
            .map_err(|e| anyhow!("invalid owner: {e}"))?;

        let raw = self
            .client
            .account()
            .fetch_account_data_static::<DirectEventContent>()
            .await
            .context("fetch m.direct failed")?;
        let mut content = match raw {
            Some(r) => r.deserialize().context("deserialize m.direct failed")?,
            None => return Ok(()), // no DMs recorded yet
        };

        let key: OwnedDirectUserIdentifier = owner.into();
        let Some(original) = content.get(&key).cloned() else {
            return Ok(());
        };

        // Set of rooms the agent is currently joined to.
        let joined: std::collections::HashSet<OwnedRoomId> = self
            .client
            .joined_rooms()
            .iter()
            .map(|r| r.room_id().to_owned())
            .collect();

        // Determine, per unique room, whether the owner is POSITIVELY gone
        // (membership Leave/Ban). Unknown membership / unknown room → NOT stale, so
        // a transient sync gap can never evict the live DM. Then classify via a
        // pure fn (deduped, order-preserving).
        let mut stale_map: std::collections::HashMap<OwnedRoomId, bool> =
            std::collections::HashMap::new();
        for room_id in &original {
            if stale_map.contains_key(room_id) {
                continue;
            }
            let positively_stale = match self.client.get_room(room_id) {
                Some(room) => matches!(
                    room.get_member(owner)
                        .await
                        .ok()
                        .flatten()
                        .map(|m| m.membership().clone()),
                    Some(MembershipState::Leave) | Some(MembershipState::Ban)
                ),
                None => false, // unknown room → keep (don't drop on uncertainty)
            };
            stale_map.insert(room_id.clone(), positively_stale);
        }
        let (kept, dropped) =
            partition_dm_rooms(&original, &|r| *stale_map.get(r).unwrap_or(&false));

        // Leave + forget rooms the owner abandoned but the agent is still in, so
        // they stop generating undecryptable-event churn on every poll.
        for room_id in &dropped {
            if !joined.contains(room_id) {
                continue;
            }
            if let Some(room) = self.client.get_room(room_id) {
                if let Err(e) = room.leave().await {
                    tracing::warn!(%room_id, "reconcile: leave stale DM failed: {e:#}");
                    continue;
                }
                if let Err(e) = room.forget().await {
                    tracing::warn!(%room_id, "reconcile: forget stale DM failed: {e:#}");
                }
                tracing::info!(%room_id, "reconcile: left+forgot stale DM (owner had left)");
            }
        }

        if kept == original {
            return Ok(()); // already clean (no dups, no positively-stale entries)
        }
        content.insert(key, kept.clone());
        self.client
            .account()
            .set_account_data(content)
            .await
            .context("rewrite m.direct failed")?;
        tracing::info!(
            owner = %owner,
            kept = kept.len(),
            dropped = dropped.len(),
            "reconcile: m.direct rewritten (duplicates + owner-left rooms removed)"
        );
        Ok(())
    }

    pub async fn send_dm(&self, target: &str, message: &str) -> Result<String> {
        let target: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid target: {e}"))?;
        // Resolve (or create) the DM room and best-effort mark it as a direct
        // chat. Shared with every media send via `ensure_dm_room` (see media.rs)
        // so text and attachments always land in the same Megolm session.
        let room = self.ensure_dm_room(target).await?;
        // Render the body as Markdown so Element (Web + X) display formatted
        // text. `text_markdown` attaches an `org.matrix.custom.html`
        // formatted_body (rendered HTML) and keeps the raw text as the plain
        // `body` fallback. Sending `text_plain` carries no formatted body, so
        // clients have nothing to render and show the raw markup verbatim.
        let resp = room
            .send(RoomMessageEventContent::text_markdown(message))
            .await
            .context("failed to send message")?;
        Ok(resp.response.event_id.to_string())
    }

    /// Like [`send_dm`](Self::send_dm) but retries the send until the homeserver
    /// acknowledges the event (returning its id) or attempts are exhausted. Use
    /// for a message that must not be silently dropped — e.g. the final
    /// one-shot reply of a run, or the error notice that explains a failure. A
    /// failed attempt means nothing landed (`room.send` only yields an event id
    /// on persistence), so retrying cannot duplicate a delivered message.
    pub async fn send_dm_reliable(&self, target: &str, message: &str) -> Result<String> {
        retry_finalize("send-dm", || self.send_dm(target, message)).await
    }

    /// Reliably send `message`, splitting it at clean boundaries into as many
    /// messages as needed so no single event approaches Matrix's size cap
    /// (`413 M_TOO_LARGE`). Use for a long one-shot reply that did not stream.
    /// Each chunk is sent with [`send_dm_reliable`](Self::send_dm_reliable); the
    /// last delivered event id is returned. See [`split_for_matrix`].
    pub async fn send_dm_chunked(&self, target: &str, message: &str) -> Result<String> {
        let mut last = String::new();
        for chunk in split_for_matrix(message, STREAM_ROLLOVER_BYTES) {
            last = self.send_dm_reliable(target, &chunk).await?;
        }
        Ok(last)
    }

    /// [`send_dm_reliable`](Self::send_dm_reliable) wrapped with a
    /// refresh-then-retry on `M_UNKNOWN_TOKEN`. Promotes the fix already proven
    /// in the 2026-07-17 incident (`send_dm_reliable_with_refresh` in
    /// `aqua-call-agent/src/bin/aqua_transcript_agent.rs`) into this shared
    /// connector crate, so every backend gets it, not just one binary.
    ///
    /// `send_dm_reliable` already retries transient failures internally
    /// (`retry_finalize`, several attempts with backoff), but all of those
    /// attempts burn against the SAME access token — a dead/rotated credential
    /// exhausts every attempt without ever refreshing it (the root cause: a
    /// daemon builds one `AgentClient` per connection cycle, but a
    /// long-running spawned task can hold a CLONE of it that outlives the
    /// cycle, so nothing ever hands that clone a later cycle's fresh token).
    /// On `M_UNKNOWN_TOKEN` specifically, reauth once
    /// ([`reauth_token_only`](Self::reauth_token_only)) and run the full
    /// reliable-send again: not a new backoff loop, just one reauth gating one
    /// more pass through the existing one.
    pub async fn send_dm_reliable_with_refresh(
        &mut self,
        target: &str,
        message: &str,
    ) -> Result<String> {
        match self.send_dm_reliable(target, message).await {
            Ok(id) => Ok(id),
            Err(e) if is_unknown_token(&e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "DM send rejected with M_UNKNOWN_TOKEN; refreshing token and retrying once"
                );
                self.reauth_token_only()
                    .await
                    .context("token refresh after M_UNKNOWN_TOKEN failed")?;
                self.send_dm_reliable(target, message)
                    .await
                    .context("DM send still failed after token refresh")
            }
            Err(e) => Err(e),
        }
    }

    /// [`send_dm_chunked`](Self::send_dm_chunked) wrapped the same way as
    /// [`send_dm_reliable_with_refresh`](Self::send_dm_reliable_with_refresh) —
    /// see that method for the full rationale.
    pub async fn send_dm_chunked_with_refresh(
        &mut self,
        target: &str,
        message: &str,
    ) -> Result<String> {
        match self.send_dm_chunked(target, message).await {
            Ok(id) => Ok(id),
            Err(e) if is_unknown_token(&e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "chunked DM send rejected with M_UNKNOWN_TOKEN; refreshing token and retrying once"
                );
                self.reauth_token_only()
                    .await
                    .context("token refresh after M_UNKNOWN_TOKEN failed")?;
                self.send_dm_chunked(target, message)
                    .await
                    .context("chunked DM send still failed after token refresh")
            }
            Err(e) => Err(e),
        }
    }

    /// Send a Markdown message into an **arbitrary already-joined room** (by room
    /// id), NOT a DM. The agent must already be a member of `room_id` (it is — it
    /// joined the owner's room to transcribe the call). Unlike [`send_dm`], this
    /// does not resolve/create a `m.direct` room: it targets a specific room, so
    /// it is the path for announcing recording state and acking participant
    /// opt-out/in **in the call room** where everyone (not just the owner) sees
    /// it. Returns the persisted event id.
    pub async fn send_to_room(&self, room_id: &str, message: &str) -> Result<String> {
        let room_id: &RoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        let room = self
            .client
            .get_room(room_id)
            .ok_or_else(|| anyhow!("room {room_id} not found (agent not joined?)"))?;
        let resp = room
            .send(RoomMessageEventContent::text_markdown(message))
            .await
            .context("failed to send room message")?;
        Ok(resp.response.event_id.to_string())
    }

    /// [`send_dm`] bounded by [`SEND_ATTEMPT_TIMEOUT`] so a server-5xx that
    /// matrix-sdk would otherwise retry internally for minutes can't silently
    /// consume the access token's whole lifetime. A timeout is surfaced as a
    /// normal error so the caller's self-heal logic runs.
    async fn send_dm_bounded(&self, target: &str, message: &str) -> Result<String> {
        match tokio::time::timeout(SEND_ATTEMPT_TIMEOUT, self.send_dm(target, message)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!(
                "send timed out after {}s (homeserver not acknowledging the event)",
                SEND_ATTEMPT_TIMEOUT.as_secs()
            )),
        }
    }

    /// Token-resilient DM send for the one-shot CLI. siwx-oidc access tokens
    /// live only ~300s and the matrix-sdk client is restored with
    /// `refresh_token: None`, so it cannot self-refresh — a `connect()` whose
    /// startup (sync + cross-signing + recovery) ate most of the token's life
    /// would then `send` with a near-dead or already-expired token and get
    /// `401 M_UNKNOWN_TOKEN`. This was the surface symptom in
    /// `~/.aqua-matrix-notify/notify.log`.
    ///
    /// Self-healing, all non-interactive (driven by the persisted refresh token
    /// / the `did:key` at `key_file`):
    ///   1. **Proactive:** if the access token has under [`TOKEN_REFRESH_MARGIN`]
    ///      of life left, rotate it via `reauth_inner()` *before* sending.
    ///   2. **Reactive token heal:** if a send fails with `M_UNKNOWN_TOKEN`
    ///      (token revoked, or it died in the request window), re-auth and retry.
    ///   3. **Fail fast on server faults:** a `5xx` / `M_UNKNOWN Internal server
    ///      error` is a homeserver bug, not a token problem — retrying or
    ///      re-authing cannot fix it and would only burn tokens, so we surface it
    ///      immediately with an actionable message. Each attempt is also bounded
    ///      by [`SEND_ATTEMPT_TIMEOUT`] so a wedged send returns in seconds.
    pub async fn send_dm_self_healing(&mut self, target: &str, message: &str) -> Result<String> {
        // 1. Proactive refresh: never send on a token that is about to expire.
        if self.token_seconds_left() < TOKEN_REFRESH_MARGIN {
            tracing::info!(
                "access token has {}s left (< {}s margin); rotating before send",
                self.token_seconds_left(),
                TOKEN_REFRESH_MARGIN
            );
            if let Err(e) = self.reauth_inner(true).await {
                // Don't hard-fail yet — the current token may still have a few
                // seconds; let the send attempt (and the reactive path) decide.
                tracing::warn!("proactive reauth failed: {e:#}; attempting send with current token");
            }
        }

        // 2. First send attempt (bounded).
        match self.send_dm_bounded(target, message).await {
            Ok(id) => return Ok(id),
            Err(e) if is_server_internal_error(&e) => {
                return Err(e).context(
                    "homeserver rejected the send with a 5xx/Internal server error — \
                     this is a server-side fault (reads/auth work, message persistence does not), \
                     not a token or client problem; retrying will not help",
                );
            }
            Err(e) if is_unknown_token(&e) => {
                tracing::warn!("send rejected with M_UNKNOWN_TOKEN; re-authenticating and retrying once");
                self.reauth_inner(true)
                    .await
                    .context("re-auth after M_UNKNOWN_TOKEN failed")?;
            }
            Err(e) => return Err(e),
        }

        // 3. Post-reauth retry (only reached on a token rejection above).
        match self.send_dm_bounded(target, message).await {
            Ok(id) => Ok(id),
            Err(e) if is_server_internal_error(&e) => Err(e).context(
                "homeserver still returns a 5xx after re-authentication — server-side send fault",
            ),
            Err(e) => Err(e).context("send still failed after re-authentication"),
        }
    }

    /// Upsert this agent's fleet-registry entry in global account data under
    /// the custom type `io.inblock.aqua.registry`. Best-effort by caller.
    pub async fn update_registry(&self, role: &str, systemd_unit: Option<&str>) -> Result<()> {
        use matrix_sdk::ruma::events::{
            AnyGlobalAccountDataEventContent, GlobalAccountDataEventType,
        };
        use matrix_sdk::ruma::serde::Raw;

        let last_online = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let content = registry::RegistryContent {
            did: self.did.clone(),
            user_id: self.user_id.to_string(),
            role: role.to_string(),
            systemd_unit: systemd_unit.map(|s| s.to_string()),
            last_online,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let raw: Raw<AnyGlobalAccountDataEventContent> = Raw::new(&content)
            .context("failed to serialize registry content")?
            .cast_unchecked();
        let event_type =
            GlobalAccountDataEventType::from(registry::REGISTRY_EVENT_TYPE.to_string());

        self.client
            .account()
            .set_account_data_raw(event_type, raw)
            .await
            .context("failed to write registry account data")?;
        Ok(())
    }

    /// Set this agent's Matrix profile display name so humans see a readable
    /// alias (e.g. "claude-channel") instead of the raw DID-derived MXID.
    /// Idempotent: skips the homeserver write when the name already matches,
    /// so reconnect cycles don't issue a redundant profile PUT every time.
    pub async fn set_display_name(&self, name: &str) -> Result<()> {
        let account = self.client.account();
        let current = account
            .get_display_name()
            .await
            .context("failed to read current display name")?;
        if current.as_deref() == Some(name) {
            return Ok(());
        }
        account
            .set_display_name(Some(name))
            .await
            .context("failed to set display name")?;
        Ok(())
    }

    /// Set this agent's Matrix profile avatar from a local image file. Mirrors
    /// [`set_display_name`]: best-effort and idempotent across reconnects. The
    /// relay re-applies this on every first sync cycle, so to avoid re-uploading
    /// (and orphaning media on the homeserver) we cache the content fingerprint
    /// of the last-applied avatar in a sentinel under the store dir and skip the
    /// upload when the file is unchanged AND the account still advertises an
    /// avatar URL.
    pub async fn set_avatar(&self, path: &Path) -> Result<()> {
        let data = std::fs::read(path)
            .with_context(|| format!("failed to read avatar file {}", path.display()))?;
        let mime = avatar_mime(&data)?;
        let fingerprint = content_fingerprint(&data);
        let sentinel = self.config.store_dir.join(".avatar-fingerprint");
        let account = self.client.account();

        if std::fs::read_to_string(&sentinel).ok().as_deref() == Some(fingerprint.as_str())
            && account
                .get_avatar_url()
                .await
                .context("failed to read current avatar url")?
                .is_some()
        {
            return Ok(());
        }

        account
            .upload_avatar(&mime, data)
            .await
            .context("failed to upload avatar")?;
        // Best-effort cache; a failed write just means we re-upload next time.
        let _ = std::fs::write(&sentinel, &fingerprint);
        Ok(())
    }

    pub async fn messages(&self, room_id: &str, limit: u32) -> Result<Vec<Message>> {
        let room_id: &RoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        let room = self
            .client
            .get_room(room_id)
            .ok_or_else(|| anyhow!("room {room_id} not found"))?;

        let mut opts = MessagesOptions::backward();
        opts.limit = UInt::from(limit);
        let resp = room
            .messages(opts)
            .await
            .context("failed to fetch messages")?;

        let mut messages = Vec::new();
        let mut utd_count: u32 = 0;
        let mut utd_session_ids: Vec<String> = Vec::new();
        for event in resp.chunk {
            let Some(event_id) = event.event_id() else {
                continue;
            };
            let Some(sender) = event.sender() else {
                continue;
            };
            let Some(timestamp) = event.timestamp() else {
                continue;
            };

            if event.kind.is_utd() {
                utd_count = utd_count.saturating_add(1);
                // Best-effort session_id from the encrypted wire content so we
                // can target a single-session backup download (matrix-sdk's
                // decrypt path only queues a best-effort backup fetch).
                if let Some(sid) = megolm_session_id_from_raw(event.raw()) {
                    if !utd_session_ids.iter().any(|s| s == &sid) {
                        utd_session_ids.push(sid);
                    }
                }
                messages.push(Message {
                    sender: sender.to_string(),
                    body: "[unable to decrypt]".into(),
                    timestamp_ms: u64::from(timestamp.0),
                    event_id: event_id.to_string(),
                });
                continue;
            }

            let Ok(deserialized) = event.raw().deserialize() else {
                continue;
            };
            if let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                msg_event,
            )) = deserialized
            {
                if let Some(original) = msg_event.as_original() {
                    let body = match &original.content.msgtype {
                        MessageType::Text(text) => text.body.clone(),
                        MessageType::Notice(notice) => notice.body.clone(),
                        MessageType::Emote(emote) => emote.body.clone(),
                        _ => continue,
                    };
                    messages.push(Message {
                        sender: original.sender.to_string(),
                        body,
                        timestamp_ms: u64::from(original.origin_server_ts.0),
                        event_id: original.event_id.to_string(),
                    });
                }
            }
        }

        // UTD recovery: pull missing megolm sessions from server-side key
        // backup. Does not pause the caller — next poll may decrypt. Peers may
        // also forward via automatic-room-key-forwarding on subsequent sync.
        if utd_count > 0 {
            tracing::warn!(
                room_id = %room_id,
                utd_count,
                sessions = ?utd_session_ids,
                "messages(): undecryptable event(s); requesting key-backup download"
            );
            if utd_session_ids.is_empty() {
                if let Err(e) = self
                    .client
                    .encryption()
                    .backups()
                    .download_room_keys_for_room(room_id)
                    .await
                {
                    tracing::warn!(
                        room_id = %room_id,
                        "messages(): room-wide key-backup download failed: {e:#}"
                    );
                } else {
                    tracing::info!(
                        room_id = %room_id,
                        "messages(): room-wide key-backup download finished"
                    );
                }
            } else {
                for sid in &utd_session_ids {
                    match self
                        .client
                        .encryption()
                        .backups()
                        .download_room_key(room_id, sid)
                        .await
                    {
                        Ok(true) => tracing::info!(
                            room_id = %room_id,
                            session_id = %sid,
                            "messages(): session key-backup download ok"
                        ),
                        Ok(false) => tracing::warn!(
                            room_id = %room_id,
                            session_id = %sid,
                            "messages(): session key-backup download skipped (backup inactive?)"
                        ),
                        Err(e) => tracing::warn!(
                            room_id = %room_id,
                            session_id = %sid,
                            "messages(): session key-backup download failed: {e:#}"
                        ),
                    }
                }
            }
        }

        messages.reverse();
        Ok(messages)
    }

    pub async fn sync_once(&self) -> Result<()> {
        self.client
            .sync_once(SyncSettings::default())
            .await
            .context("sync failed")?;
        Ok(())
    }

    /// Show a Matrix typing indicator ("<agent> is typing…") to `target` until
    /// the returned guard is dropped. Returns `None` if no DM room exists yet.
    /// The guard refreshes the notice every few seconds (the homeserver expires
    /// it after ~4s) and clears it on drop — use it to signal "working" during a
    /// slow operation like an LLM call.
    pub async fn typing_guard(&self, target: &str) -> Option<TypingGuard> {
        let target: &UserId = target.try_into().ok()?;
        let room = self.find_dm_room(target).await?;
        Some(TypingGuard::start(room))
    }

    /// Begin a streaming reply to `target`: sends a placeholder message now and
    /// returns a handle whose [`ReplyStream::push`] / [`ReplyStream::finish`]
    /// edit that same message in place (Matrix `m.replace`), so an answer
    /// appears to type out instead of landing as one block. Errors if no DM room
    /// exists yet — callers should fall back to [`AgentClient::send_dm`].
    pub async fn reply_stream(&self, target: &str) -> Result<ReplyStream> {
        let target_uid: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid target: {e}"))?;
        let room = self
            .find_dm_room(target_uid)
            .await
            .ok_or_else(|| anyhow!("no DM room with {target} for a streaming reply"))?;
        ReplyStream::start(room).await
    }
}

/// How often to push an in-place edit while streaming. Editing per token would
/// flood the room with events (each a separate, E2E-encrypted `m.replace`); one
/// edit every ~700ms reads as smooth typing without the spam.
const STREAM_EDIT_INTERVAL: Duration = Duration::from_millis(700);

/// Soft cap on the markdown held in a *single* streamed message. Past this the
/// stream **rolls over**: the current message is finalized at a clean boundary
/// (never mid-sentence) and a fresh message continues the reply
/// (see [`ReplyStream::push`] / [`split_for_matrix`]).
///
/// Why this sits so far below Matrix's 65,536-byte hard event cap: a streamed
/// reply is delivered as an `m.replace` **edit** of **markdown**, **E2E-encrypted**.
/// Each of those multiplies the wire size of the body —
///   * markdown gains an HTML `formatted_body` (≈1.2–1.5× for prose, more for lists/code),
///   * an edit embeds a full **second copy** of the content in `m.new_content` (≈2×),
///   * Megolm encryption base64-expands the whole event (≈1.33×).
/// So `B` bytes of markdown become roughly `2 × 1.4 × 1.33 × B ≈ 3.7·B` (plus JSON
/// overhead) on the wire. At the old 16,000-byte cap that reached ~60–120 KB and
/// tripped **413 M_TOO_LARGE**; 6,000 B keeps even a heavily-formatted encrypted
/// edit comfortably under 64 KiB.
const STREAM_ROLLOVER_BYTES: usize = 6_000;

/// Don't finalize a rolled-over message smaller than this — avoids a flurry of
/// tiny messages when an early paragraph break would otherwise win. The splitter
/// prefers the *largest* clean boundary ≤ budget, falling back through boundary
/// kinds (paragraph → line → sentence → word → hard cut).
const STREAM_MIN_SPLIT_BYTES: usize = 1_500;

/// Safety bound on how many messages one reply may fan out into, so a runaway
/// (or adversarial) output cannot flood a room. Beyond this the tail is truncated.
const STREAM_MAX_MESSAGES: usize = 50;

/// Hold the FIRST message of a streamed reply back until the buffer carries at
/// least this many bytes, so the receiver's push notification previews the first
/// lines of the answer instead of a bare placeholder. The typing indicator covers
/// the brief wait; a short reply that never reaches this is sent whole by
/// [`ReplyStream::finish`]. ~120 bytes ≈ a line or two — enough to be meaningful.
const FIRST_MESSAGE_MIN_BYTES: usize = 120;

/// The *final* transmission of a reply must not be silently dropped: throttled
/// intermediate edits are best-effort (each is superseded by the next), but the
/// last edit / one-shot send carries the authoritative, complete text. If its
/// `room.send` fails (a transient network blip, a token-rotation race, an
/// encryption hiccup) the user is left looking at a half-streamed message that
/// never resolves. So the finalize path retries until the homeserver
/// acknowledges the event — a returned event id is that acknowledgement.
const FINALIZE_MAX_ATTEMPTS: usize = 5;
/// Linear backoff base between finalize attempts (attempt N waits N×base).
const FINALIZE_RETRY_BASE: Duration = Duration::from_millis(500);

/// Proactively rotate the access token before a one-shot send when it has less
/// than this much life left. siwx-oidc tokens live ~300s and a `connect()`'s
/// own startup (sync + cross-signing + recovery) can consume much of that, so a
/// generous margin guarantees the send runs on a token that won't expire
/// mid-request. See [`AgentClient::send_dm_self_healing`].
const TOKEN_REFRESH_MARGIN: u64 = 60;

/// Retry `op` until it returns `Ok` (the send was acknowledged by the server)
/// or [`FINALIZE_MAX_ATTEMPTS`] is exhausted, with linear backoff. `op`'s `Ok`
/// value is the homeserver's confirmation (an event id), so a success here is a
/// *programmatic guarantee the message was transmitted*, not a hopeful
/// fire-and-forget. On exhaustion the last error is returned so the caller can
/// surface it. Safe to retry: `room.send` only yields an event id once the
/// event is persisted, so a failed attempt means nothing landed.
async fn retry_finalize<T, F, Fut>(what: &str, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_err = None;
    for attempt in 1..=FINALIZE_MAX_ATTEMPTS {
        match op().await {
            Ok(v) => {
                if attempt > 1 {
                    tracing::info!("{what}: transmission confirmed on attempt {attempt}");
                }
                return Ok(v);
            }
            Err(e) => {
                tracing::warn!(
                    "{what}: transmission attempt {attempt}/{FINALIZE_MAX_ATTEMPTS} failed: {e:#}"
                );
                last_err = Some(e);
                if attempt < FINALIZE_MAX_ATTEMPTS {
                    tokio::time::sleep(FINALIZE_RETRY_BASE * attempt as u32).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("{what}: transmission failed with no error recorded")))
}

/// Generic shape of the try -> (on `M_UNKNOWN_TOKEN`) reauth-once -> retry-once
/// branching that every `*_with_refresh` method above implements directly
/// against `self` (see [`AgentClient::send_dm_reliable_with_refresh`]).
///
/// This free function exists ONLY so that branching shape is unit-testable in
/// isolation with injected fake errors: a real `AgentClient` needs a live
/// matrix-sdk `Client` to construct, which a unit test can't do. The
/// `*_with_refresh` methods do NOT call this helper — a method that built one
/// closure borrowing `&self` (the op) and another borrowing `&mut self` (the
/// reauth) would hold both borrows alive simultaneously as soon as they're
/// passed to a shared call, which the borrow checker rejects. Each method
/// instead writes the same shape directly as sequential statements against
/// `self`, exactly mirroring what this helper proves correct: try once; on a
/// token rejection, reauth once and retry once; any other error (or a reauth
/// failure) propagates without a second attempt.
#[cfg(test)]
async fn reauth_then_retry<T, Op, OpFut, Reauth, ReauthFut>(mut op: Op, reauth: Reauth) -> Result<T>
where
    Op: FnMut() -> OpFut,
    OpFut: std::future::Future<Output = Result<T>>,
    Reauth: FnOnce() -> ReauthFut,
    ReauthFut: std::future::Future<Output = Result<()>>,
{
    match op().await {
        Ok(v) => Ok(v),
        Err(e) if is_unknown_token(&e) => {
            reauth()
                .await
                .context("token refresh after M_UNKNOWN_TOKEN failed")?;
            op().await.context("still failed after token refresh")
        }
        Err(e) => Err(e),
    }
}

/// RAII typing indicator, created by [`AgentClient::typing_guard`]. Refreshes
/// the `m.typing` notice on a timer and clears it on drop.
pub struct TypingGuard {
    room: matrix_sdk::Room,
    keepalive: tokio::task::JoinHandle<()>,
}

impl TypingGuard {
    fn start(room: matrix_sdk::Room) -> Self {
        let r = room.clone();
        let keepalive = tokio::spawn(async move {
            // The homeserver expires a typing notice after ~4s; refresh inside
            // that window. matrix-sdk debounces the actual network sends.
            loop {
                if r.typing_notice(true).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
        Self { room, keepalive }
    }
}

impl Drop for TypingGuard {
    fn drop(&mut self) {
        self.keepalive.abort();
        // Drop can't be async; fire-and-forget the "stopped typing" notice.
        let room = self.room.clone();
        tokio::spawn(async move {
            let _ = room.typing_notice(false).await;
        });
    }
}

/// A reply that is edited in place as content arrives, created by
/// [`AgentClient::reply_stream`]. Backed by one message plus throttled
/// `m.replace` edits — the official Matrix way to approximate streaming, since
/// the protocol has no token-stream primitive.
///
/// When a reply outgrows [`STREAM_ROLLOVER_BYTES`] it transparently **rolls over**
/// onto a new message at a clean boundary, so an arbitrarily long answer is
/// delivered as a sequence of readable messages and no single edit can ever
/// exceed Matrix's event-size cap (the `413 M_TOO_LARGE` failure mode).
pub struct ReplyStream {
    room: matrix_sdk::Room,
    /// The *current* (still editable) message; rollover advances this. `None`
    /// until the first message is actually sent — we hold it back (see
    /// [`FIRST_MESSAGE_MIN_BYTES`]) so the receiver's push notification previews
    /// real text rather than a bare placeholder.
    event_id: Option<OwnedEventId>,
    /// Markdown shown in the current message only (earlier rolled-over messages
    /// are already finalized and frozen).
    buf: String,
    last_edit: Instant,
    pending: bool,
    /// How many messages this reply has opened so far (0 before the first send).
    /// Used to bound fan-out and to know whether any rollover has happened in
    /// `finish`.
    messages: usize,
}

impl ReplyStream {
    async fn start(room: matrix_sdk::Room) -> Result<Self> {
        // Deliberately send NOTHING yet: a placeholder "…" would fire a push
        // notification with no content. The first real message is sent by `push`
        // once the buffer is meaningful, or by `finish` for a short reply. The
        // caller shows a typing indicator until then.
        Ok(Self {
            room,
            event_id: None,
            buf: String::new(),
            last_edit: Instant::now(),
            pending: false,
            messages: 0,
        })
    }

    /// Whether the first real message has been sent yet. The caller keeps its
    /// typing indicator up until this is true, so there is no silent gap while the
    /// first chunk is held back for a meaningful notification.
    pub fn has_started(&self) -> bool {
        self.event_id.is_some()
    }

    /// Send the first message as a NEW message carrying the buffer so far, so the
    /// receiver's notification previews the first lines. Best-effort: on failure
    /// we stay un-started and retry on the next `push` / `finish`.
    async fn send_first(&mut self) {
        match self.send_new(&render_streaming(&self.buf)).await {
            Ok(ev) => {
                self.event_id = Some(ev);
                self.messages = 1;
                self.last_edit = Instant::now();
                self.pending = false;
            }
            Err(e) => tracing::warn!("reply-stream: first message send failed (will retry): {e:#}"),
        }
    }

    /// Append `chunk` to the reply, editing the message in place at most once
    /// per [`STREAM_EDIT_INTERVAL`]. Intermediate states get a cursor and
    /// balanced code fences so half-streamed Markdown still renders cleanly.
    ///
    /// If the live message outgrows [`STREAM_ROLLOVER_BYTES`] it is finalized at
    /// a clean boundary and a new message continues the reply — so no edit ever
    /// approaches the event-size cap.
    ///
    /// **Intermediate edits are best-effort and never fail the caller.** A
    /// transient send error here (including a stray oversize event) is logged and
    /// swallowed: streaming a reply must never abort the work that is producing
    /// it. Only [`finish`](Self::finish) (the authoritative last write) surfaces
    /// errors.
    pub async fn push(&mut self, chunk: &str) -> Result<()> {
        self.buf.push_str(chunk);
        self.pending = true;
        // No live message yet: hold the first send back until the buffer carries
        // enough for a meaningful push notification (the first lines). Until then
        // there is nothing to roll over or edit; the caller's typing indicator
        // covers the wait.
        if self.event_id.is_none() {
            if self.buf.len() >= FIRST_MESSAGE_MIN_BYTES {
                self.send_first().await;
            }
            return Ok(());
        }
        // Roll over *before* the next edit, so an oversize edit is never sent.
        while self.buf.len() > STREAM_ROLLOVER_BYTES && self.messages < STREAM_MAX_MESSAGES {
            if !self.roll_over().await {
                break; // couldn't open a continuation; degrade gracefully
            }
        }
        if self.last_edit.elapsed() >= STREAM_EDIT_INTERVAL {
            let rendered = render_streaming(&self.buf);
            self.edit_best_effort(&rendered).await;
            self.last_edit = Instant::now();
            self.pending = false;
        }
        Ok(())
    }

    /// Replace the whole body of the **current** message (does not append).
    /// Throttled like [`push`]. Used for progress dashboards that rewrite
    /// status in place (e.g. media-render % / ETA). Best-effort intermediates.
    pub async fn set(&mut self, text: &str) -> Result<()> {
        self.buf = text.to_string();
        self.pending = true;
        if self.event_id.is_none() {
            if self.buf.len() >= FIRST_MESSAGE_MIN_BYTES {
                self.send_first().await;
            }
            return Ok(());
        }
        if self.last_edit.elapsed() >= STREAM_EDIT_INTERVAL {
            let rendered = render_streaming(&self.buf);
            self.edit_best_effort(&rendered).await;
            self.last_edit = Instant::now();
            self.pending = false;
        }
        Ok(())
    }

    /// Replace the whole body and edit **immediately** (no throttle). Use on
    /// stage boundaries so the user sees each milestone without waiting 700ms.
    /// If no message exists yet, sends the first message now.
    pub async fn set_now(&mut self, text: &str) -> Result<()> {
        self.buf = text.to_string();
        if self.event_id.is_none() {
            self.send_first().await;
            return Ok(());
        }
        let rendered = render_streaming(&self.buf);
        self.edit_best_effort(&rendered).await;
        self.last_edit = Instant::now();
        self.pending = false;
        Ok(())
    }

    /// Finalize the reply across however many messages it spans. `final_text`
    /// (the authoritative full result) replaces the buffer **only when no
    /// rollover has happened** — once earlier messages are frozen, replacing the
    /// whole text would duplicate their content, so the streamed tail is used
    /// instead. The text is split at clean boundaries into one edit of the
    /// current message plus any continuation messages, each retried until the
    /// homeserver acknowledges it (the final write is the one the user keeps).

    /// Replace the whole body of the **current** message (does not append).
    /// Throttled like [`push`]. Used for progress dashboards that rewrite
    /// status in place (e.g. media-render % / ETA). Best-effort intermediates.
    pub async fn set(&mut self, text: &str) -> Result<()> {
        self.buf = text.to_string();
        self.pending = true;
        if self.event_id.is_none() {
            if self.buf.len() >= FIRST_MESSAGE_MIN_BYTES {
                self.send_first().await;
            }
            return Ok(());
        }
        if self.last_edit.elapsed() >= STREAM_EDIT_INTERVAL {
            let rendered = render_streaming(&self.buf);
            self.edit_best_effort(&rendered).await;
            self.last_edit = Instant::now();
            self.pending = false;
        }
        Ok(())
    }

    /// Replace the whole body and edit **immediately** (no throttle). Use on
    /// stage boundaries so the user sees each milestone without waiting 700ms.
    /// If no message exists yet, sends the first message now.
    pub async fn set_now(&mut self, text: &str) -> Result<()> {
        self.buf = text.to_string();
        if self.event_id.is_none() {
            self.send_first().await;
            return Ok(());
        }
        let rendered = render_streaming(&self.buf);
        self.edit_best_effort(&rendered).await;
        self.last_edit = Instant::now();
        self.pending = false;
        Ok(())
    }

    pub async fn finish(self, final_text: Option<&str>) -> Result<()> {
        let text = if self.messages <= 1 {
            final_text
                .map(|s| s.to_string())
                .unwrap_or_else(|| self.buf.clone())
        } else {
            // Rollover already froze the earlier messages with streamed content.
            self.buf.clone()
        };
        let text = if text.trim().is_empty() {
            "(no output)".to_string()
        } else {
            text
        };
        let chunks = split_for_matrix(&text, STREAM_ROLLOVER_BYTES);
        let first = chunks.first().cloned().unwrap_or_default();
        // If a live message exists, the first chunk replaces it (edit); otherwise
        // (a short reply held back below the first-flush threshold, or a failed
        // first send) the first chunk is sent as a brand-new message so it still
        // lands and notifies meaningfully. The rest are fresh messages. All must
        // land — retry each until the homeserver acknowledges it.
        if self.event_id.is_some() {
            retry_finalize("reply-finalize", || self.edit(&first)).await?;
        } else {
            retry_finalize("reply-finalize", || self.send_plain(&first)).await?;
        }
        for chunk in chunks.iter().skip(1) {
            retry_finalize("reply-continuation", || self.send_plain(chunk)).await?;
        }
        Ok(())
    }

    /// Freeze the current message at a clean boundary and open a fresh one for
    /// the remainder. Returns `false` (without disturbing state) if a
    /// continuation message can't be opened, so the caller can degrade instead
    /// of looping. An open code fence is carried across the split.
    async fn roll_over(&mut self) -> bool {
        let cut = pick_boundary(&self.buf, STREAM_ROLLOVER_BYTES);
        let raw_head = &self.buf[..cut];
        let head = match raw_head.trim_end() {
            h if !h.is_empty() => h.to_string(),
            _ => raw_head.to_string(),
        };
        let (head_final, fence_open) = close_open_fence(&head);
        let tail = self.buf[cut..].trim_start_matches('\n').to_string();
        let new_buf = if fence_open { format!("```\n{tail}") } else { tail };
        // Open the continuation WITH its content (not a bare "…") so its push
        // notification, if any, previews real text. Do it FIRST; on failure leave
        // everything untouched.
        let new_ev = match self.send_new(&render_streaming(&new_buf)).await {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!("reply-rollover: cannot open continuation message: {e:#}");
                return false;
            }
        };
        // Freeze the current message at the clean head (no cursor). Retried, but
        // best-effort: a frozen message is never re-edited, so don't abort on it.
        if let Err(e) = retry_finalize("reply-rollover", || self.edit(&head_final)).await {
            tracing::warn!("reply-rollover: failed to finalize a rolled-over message: {e:#}");
        }
        self.event_id = Some(new_ev);
        self.messages += 1;
        self.buf = new_buf;
        // The continuation was just sent with current content; next edit waits a
        // full interval.
        self.last_edit = Instant::now();
        true
    }

    /// Send `body` as a fresh message and return its event id (a new live
    /// message). Used to open a rollover continuation and the first message —
    /// always with real content so it never notifies as a bare placeholder.
    async fn send_new(&self, body: &str) -> Result<OwnedEventId> {
        let resp = self
            .room
            .send(RoomMessageEventContent::text_markdown(body))
            .await
            .context("failed to open continuation message")?;
        Ok(resp.response.event_id.clone())
    }

    /// A best-effort in-place edit: logs and swallows any send error so a
    /// throttled streaming update can never abort the run producing the reply.
    async fn edit_best_effort(&self, body: &str) {
        if let Err(e) = self.edit(body).await {
            tracing::warn!("reply-stream: dropped a best-effort streaming edit: {e:#}");
        }
    }

    async fn edit(&self, body: &str) -> Result<()> {
        // Only valid once a live message exists; callers (throttled edit, rollover
        // freeze, finish-with-event) ensure that. Defensive no-op otherwise.
        let Some(event_id) = self.event_id.clone() else {
            return Ok(());
        };
        // Build the replacement directly rather than via Room::make_edit_event,
        // which fetches the target event from the server on every call (a
        // round-trip per edit, and racy right after we send the message).
        // We are the author and already hold the event id, so this is safe.
        let content = RoomMessageEventContent::text_markdown(body)
            .make_replacement(ReplacementMetadata::new(event_id, None));
        self.room
            .send(content)
            .await
            .context("failed to send streaming edit")?;
        Ok(())
    }

    /// Send `body` as a brand-new message (not an edit). Used for continuation
    /// messages: a fresh `m.room.message` carries no `m.new_content` copy, so it
    /// is far smaller on the wire than the equivalent edit.
    async fn send_plain(&self, body: &str) -> Result<()> {
        let content = RoomMessageEventContent::text_markdown(body);
        self.room
            .send(content)
            .await
            .context("failed to send continuation message")?;
        Ok(())
    }
}

/// Render an in-progress buffer: cap length, balance an odd ``` fence so a
/// half-streamed code block doesn't swallow the rest, and append a cursor.
fn render_streaming(buf: &str) -> String {
    let mut s = truncate_bytes(buf, STREAM_ROLLOVER_BYTES);
    if s.matches("```").count() % 2 == 1 {
        s.push_str("\n```");
    }
    s.push_str(" ▌");
    s
}

/// Split `text` into messages each ≤ `budget` bytes, cutting at the cleanest
/// available boundary so a continuation never starts mid-sentence. This is what
/// turns an arbitrarily long reply into a sequence of readable Matrix messages
/// instead of one oversize event (`413 M_TOO_LARGE`).
///
/// Per chunk the boundary preference is: a paragraph break (`\n\n`), then a line
/// break (`\n`), then a sentence end (`. ` / `! ` / `? `), then a word break
/// (space), then a hard UTF-8-safe cut. An open ``` code fence is carried across
/// the cut — closed at the end of one chunk and reopened at the start of the next
/// — so a split code block renders cleanly on both sides.
fn split_for_matrix(text: &str, budget: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut reopen = false;
    while !rest.is_empty() {
        let prefix = if reopen { "```\n" } else { "" };
        let avail = budget.saturating_sub(prefix.len()).max(1);
        // Whole remainder fits → final chunk.
        if rest.len() <= avail {
            out.push(close_if_needed(&format!("{prefix}{rest}")));
            return out;
        }
        // Safety valve: the last allowed message carries a truncated remainder.
        if out.len() + 1 >= STREAM_MAX_MESSAGES {
            let body = truncate_bytes(rest, avail);
            out.push(close_if_needed(&format!("{prefix}{body}")));
            return out;
        }
        let cut = pick_boundary(rest, avail);
        let raw_head = &rest[..cut];
        let head = match raw_head.trim_end() {
            h if !h.is_empty() => h,
            _ => raw_head,
        };
        let (piece, opened) = close_open_fence(&format!("{prefix}{head}"));
        out.push(piece);
        reopen = opened;
        rest = rest[cut..].trim_start_matches('\n');
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Pick the byte index in `s` at which to cut so the head is ≤ `avail` bytes and
/// ends at the cleanest boundary available (see [`split_for_matrix`]). The
/// returned index is always on a UTF-8 char boundary and ≥ 1, so callers make
/// progress. Boundaries shorter than [`STREAM_MIN_SPLIT_BYTES`] are skipped in
/// favour of a later (larger) boundary, except the final hard cut.
fn pick_boundary(s: &str, avail: usize) -> usize {
    let mut cap = s.len().min(avail);
    while cap > 0 && !s.is_char_boundary(cap) {
        cap -= 1;
    }
    if cap == 0 {
        // Degenerate: advance one char so we never stall.
        let mut e = 1;
        while e < s.len() && !s.is_char_boundary(e) {
            e += 1;
        }
        return e;
    }
    // Don't accept a boundary that would make the head smaller than half the
    // window (avoids tiny messages), but never demand more than the configured
    // minimum — so small budgets still honour word/sentence boundaries.
    let floor = STREAM_MIN_SPLIT_BYTES.min(cap / 2).max(1);
    let window = &s[..cap];
    // 1. Paragraph break.
    if let Some(p) = window.rfind("\n\n") {
        let e = p + 2;
        if e >= floor {
            return e;
        }
    }
    // 2. Single line break.
    if let Some(p) = window.rfind('\n') {
        let e = p + 1;
        if e >= floor {
            return e;
        }
    }
    // 3. Sentence end.
    if let Some(e) = last_sentence_end(window) {
        if e >= floor {
            return e;
        }
    }
    // 4. Word break.
    if let Some(p) = window.rfind(' ') {
        let e = p + 1;
        if e >= floor {
            return e;
        }
    }
    // 5. Hard cut at the largest char boundary ≤ avail.
    cap
}

/// Largest index `e` such that `s[..e]` ends with a sentence terminator
/// (`. `, `! `, `? `), or `None` if there is none.
fn last_sentence_end(s: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    for pat in [". ", "! ", "? "] {
        if let Some(p) = s.rfind(pat) {
            let e = p + pat.len();
            best = Some(best.map_or(e, |b| b.max(e)));
        }
    }
    best
}

/// If `s` has an odd number of ``` fences (i.e. ends inside a code block), append
/// a closing fence. Returns the (possibly closed) string and whether it had to
/// close one — the caller reopens the fence on the next chunk when so.
fn close_open_fence(s: &str) -> (String, bool) {
    if s.matches("```").count() % 2 == 1 {
        (format!("{s}\n```"), true)
    } else {
        (s.to_string(), false)
    }
}

/// [`close_open_fence`] keeping only the balanced string.
fn close_if_needed(s: &str) -> String {
    close_open_fence(s).0
}

/// Truncate `s` to at most `max_bytes`, on a UTF-8 char boundary.
fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str("\n[…truncated]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Strip whitespace and fence markers so we can assert no content was lost
    /// across a split regardless of where boundaries fell.
    fn words(s: &str) -> Vec<String> {
        s.replace("```", " ")
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn split_short_text_is_one_chunk() {
        assert_eq!(split_for_matrix("hello world", 6_000), vec!["hello world"]);
    }

    #[test]
    fn split_empty_text_is_one_empty_chunk() {
        assert_eq!(split_for_matrix("", 6_000), vec![String::new()]);
    }

    #[test]
    fn split_respects_budget_and_preserves_content() {
        let text = "The quick brown fox jumps. ".repeat(1_000); // ~27 KB of sentences
        let chunks = split_for_matrix(&text, 4_000);
        assert!(chunks.len() >= 5, "expected several chunks, got {}", chunks.len());
        for c in &chunks {
            assert!(c.len() <= 4_000, "chunk of {} bytes exceeds budget", c.len());
        }
        // No words dropped or duplicated.
        let rejoined: String = chunks.join(" ");
        assert_eq!(words(&rejoined), words(&text));
    }

    #[test]
    fn split_prefers_paragraph_boundary() {
        let a = "A".repeat(3_500);
        let b = "B".repeat(3_500);
        let text = format!("{a}\n\n{b}");
        let chunks = split_for_matrix(&text, 6_000);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].starts_with('A') && chunks[0].ends_with('A'));
        assert!(chunks[1].starts_with('B'));
        // The paragraph break, not a mid-run cut, was used.
        assert_eq!(chunks[0].len(), 3_500);
    }

    #[test]
    fn split_never_cuts_mid_word_when_a_space_exists() {
        // distinctive tokens so a mid-word cut would be detectable. Kept under
        // the STREAM_MAX_MESSAGES flood guard at this budget (≈37 chunks).
        let text = (0..2_000).map(|i| format!("tok{i:05} ")).collect::<String>();
        let chunks = split_for_matrix(&text, 500);
        assert!(chunks.len() > 1);
        // Every token in the source survives intact in some chunk.
        let rejoined: String = chunks.join(" ");
        assert_eq!(words(&rejoined), words(&text));
        // And no chunk ends with a partial token (would mean a mid-word cut).
        for c in &chunks {
            let tail = c.trim_end();
            if let Some(last) = tail.split_whitespace().last() {
                assert!(
                    last.starts_with("tok") && last.len() == 8,
                    "chunk ends with a partial token: {last:?}"
                );
            }
        }
    }

    #[test]
    fn split_carries_code_fence_across_boundary() {
        let body = "let x = 1;\n".repeat(800); // big code block forces a split inside it
        let text = format!("intro paragraph\n\n```rust\n{body}```\nclosing remarks");
        let chunks = split_for_matrix(&text, 3_000);
        assert!(chunks.len() >= 2);
        for c in &chunks {
            assert_eq!(
                c.matches("```").count() % 2,
                0,
                "chunk has an unbalanced code fence"
            );
        }
    }

    #[test]
    fn split_hard_cuts_when_no_boundary_exists() {
        let text = "x".repeat(10_000); // no whitespace at all
        let chunks = split_for_matrix(&text, 2_000);
        assert!(chunks.len() >= 5);
        for c in &chunks {
            assert!(c.len() <= 2_000);
        }
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn split_is_utf8_safe() {
        let text = "héllo wörld ".repeat(500); // multi-byte chars near cut points
        let chunks = split_for_matrix(&text, 300);
        // Each chunk is valid UTF-8 by construction (String); assert content kept.
        let rejoined: String = chunks.join(" ");
        assert_eq!(words(&rejoined), words(&text));
    }

    #[test]
    fn close_open_fence_balances_odd_fences() {
        let (closed, opened) = close_open_fence("```rust\nlet x = 1;");
        assert!(opened);
        assert_eq!(closed.matches("```").count(), 2);
        let (same, opened) = close_open_fence("no code here");
        assert!(!opened);
        assert_eq!(same, "no code here");
    }

    #[test]
    fn avatar_mime_detects_by_magic_bytes() {
        assert_eq!(avatar_mime(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap().to_string(), "image/jpeg");
        assert_eq!(
            avatar_mime(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]).unwrap().to_string(),
            "image/png"
        );
        assert_eq!(avatar_mime(b"GIF89a\x00\x00").unwrap().to_string(), "image/gif");
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBP");
        assert_eq!(avatar_mime(&webp).unwrap().to_string(), "image/webp");
    }

    #[test]
    fn avatar_mime_rejects_unknown() {
        assert!(avatar_mime(b"not an image at all").is_err());
        assert!(avatar_mime(&[]).is_err());
        // A JPEG file misnamed .png must STILL be detected as jpeg by content.
        assert_eq!(avatar_mime(&[0xFF, 0xD8, 0xFF, 0x00]).unwrap().to_string(), "image/jpeg");
    }

    #[test]
    fn content_fingerprint_is_stable_and_distinguishing() {
        let a = content_fingerprint(b"hello");
        let b = content_fingerprint(b"hello");
        let c = content_fingerprint(b"world");
        assert_eq!(a, b, "same bytes -> same fingerprint (idempotency)");
        assert_ne!(a, c, "different bytes -> different fingerprint");
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn config_file_roundtrip() {
        let dir = std::env::temp_dir().join("aqua-matrix-agent-test");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        // Load from nonexistent file returns defaults
        let cfg = ConfigFile::load(&path).unwrap();
        assert!(cfg.oidc.client_id.is_none());
        assert!(cfg.oidc.redirect_uri.is_none());

        // Save and reload
        let mut cfg = ConfigFile::default();
        cfg.oidc.client_id = Some("test-id-123".to_string());
        cfg.oidc.redirect_uri = Some("http://localhost:0/callback".to_string());
        cfg.save(&path).unwrap();

        let loaded = ConfigFile::load(&path).unwrap();
        assert_eq!(loaded.oidc.client_id.as_deref(), Some("test-id-123"));
        assert_eq!(
            loaded.oidc.redirect_uri.as_deref(),
            Some("http://localhost:0/callback")
        );

        // Verify the TOML format is human-readable
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("[oidc]"));
        assert!(contents.contains("client_id = \"test-id-123\""));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partition_dm_rooms_dedups_and_drops_stale() {
        // Mirrors the 2026-06-06 incident: m.direct[owner] = [bND, bND, Ejp];
        // owner left Ejp (positively stale). Expect bND once kept, Ejp dropped.
        let bnd = RoomId::parse("!bNDjtSpZzYnJQTBWvo:matrix.inblock.io").unwrap();
        let ejp = RoomId::parse("!EjpPLRYTPVsWdqrtGc:matrix.inblock.io").unwrap();
        let original = vec![bnd.clone(), bnd.clone(), ejp.clone()];
        let stale_set: std::collections::HashSet<OwnedRoomId> =
            [ejp.clone()].into_iter().collect();
        let (kept, dropped) = partition_dm_rooms(&original, &|r| stale_set.contains(r));
        assert_eq!(kept, vec![bnd], "kept holds the single live DM, deduped");
        assert_eq!(dropped, vec![ejp], "dropped holds the room the owner left");
    }

    #[test]
    fn partition_dm_rooms_no_stale_preserves_order_deduped() {
        // Conservative path: nothing positively stale → keep all (deduped), drop none.
        let a = RoomId::parse("!aaa:matrix.inblock.io").unwrap();
        let b = RoomId::parse("!bbb:matrix.inblock.io").unwrap();
        let original = vec![a.clone(), b.clone(), a.clone()];
        let (kept, dropped) = partition_dm_rooms(&original, &|_| false);
        assert_eq!(kept, vec![a, b], "first-seen order preserved, duplicate dropped");
        assert!(dropped.is_empty());
    }

    /// UTD recovery: session_id extraction from Megolm wire JSON (2026-07-16).
    /// Without this, messages() cannot target key-backup download per session.
    #[test]
    fn megolm_session_id_from_encrypted_event_json() {
        let raw = r#"{
            "type": "m.room.encrypted",
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "curve25519:gUDDkdwmehNQniXLEbCuYearf2j+IfcSFUdQSktHNGY",
                "session_id": "COAl/LHf66w8y/WuCCrLuL/glWitX9bS+LQMvq/vt8c",
                "ciphertext": "deadbeef"
            },
            "event_id": "$evt1",
            "sender": "@alice:example.org",
            "origin_server_ts": 1
        }"#;
        assert_eq!(
            megolm_session_id_from_json(raw).as_deref(),
            Some("COAl/LHf66w8y/WuCCrLuL/glWitX9bS+LQMvq/vt8c")
        );
    }

    #[test]
    fn megolm_session_id_missing_on_cleartext() {
        let raw = r#"{"type":"m.room.message","content":{"msgtype":"m.text","body":"hi"}}"#;
        assert_eq!(megolm_session_id_from_json(raw), None);
    }

    #[test]
    fn megolm_session_id_rejects_garbage() {
        assert_eq!(megolm_session_id_from_json("not-json"), None);
        assert_eq!(megolm_session_id_from_json("{}"), None);
    }

    /// Source-level contract: UTD path in messages() must request key-backup
    /// download. Removing that block re-opens permanent room UTD after store loss.
    #[test]
    fn messages_utd_path_requests_key_backup_download() {
        let src = include_str!("lib.rs");
        assert!(
            src.contains("download_room_key")
                && src.contains("undecryptable event(s); requesting key-backup download"),
            "AgentClient::messages UTD recovery (key-backup download) must remain"
        );
        let recovery = include_str!("recovery.rs");
        assert!(
            recovery.contains("download_joined_room_keys")
                && recovery.contains("download_room_keys_for_room"),
            "cold-start SSSS restore must pull room keys from backup"
        );
    }

    #[test]
    fn unknown_token_not_classified_as_server_error() {
        // Regression: "M_UNKNOWN_TOKEN" contains the substring "M_UNKNOWN", so a naive
        // is_server_internal_error swallowed a dead-token error and the server-error arm
        // (checked before is_unknown_token in send_dm_self_healing) skipped the reactive
        // re-auth. A token rejection must classify as unknown-token ONLY; a bare
        // M_UNKNOWN / 500 must classify as server-error ONLY.
        let token_err = anyhow::anyhow!(
            "the homeserver returned an error: M_UNKNOWN_TOKEN: Token is not active"
        );
        assert!(is_unknown_token(&token_err), "token rejection should be unknown-token");
        assert!(
            !is_server_internal_error(&token_err),
            "token rejection must NOT be classified as a server internal error"
        );

        let server_err =
            anyhow::anyhow!("the homeserver returned an error: M_UNKNOWN (status_code: 500)");
        assert!(
            is_server_internal_error(&server_err),
            "bare M_UNKNOWN/500 is a server internal error"
        );
        assert!(!is_unknown_token(&server_err), "a server fault is not a token rejection");
    }

    #[test]
    fn stable_device_id_is_deterministic() {
        // Same DID always derives the same device_id: this is what makes the
        // default (no AGENT_DEVICE_ID) stable across logins and restarts.
        let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        assert_eq!(stable_device_id(did), stable_device_id(did));
    }

    #[test]
    fn stable_device_id_is_distinct_per_did() {
        // Different agents (DIDs) must not collide onto the same Synapse device.
        let a = stable_device_id("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");
        let b = stable_device_id("did:pkh:eip155:1:0x0000000000000000000000000000000000000001");
        assert_ne!(a, b);
    }

    #[test]
    fn stable_device_id_is_a_valid_device_id() {
        // Synapse device_ids must be compact ASCII with no whitespace. We also
        // pin the documented AQUA_ prefix + 12 lowercase-hex chars scheme.
        let id = stable_device_id("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");
        assert!(id.starts_with("AQUA_"), "expected AQUA_ prefix, got {id}");
        assert_eq!(id.len(), "AQUA_".len() + 12, "expected 5 + 12 chars, got {id}");
        assert!(!id.chars().any(|c| c.is_whitespace()), "must contain no whitespace");
        assert!(id.is_ascii(), "must be ASCII");
        let hex = &id["AQUA_".len()..];
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix must be lowercase hex, got {hex}"
        );
    }

    #[test]
    fn effective_device_id_resolution() {
        let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        // Explicit id honoured, surrounding whitespace trimmed.
        assert_eq!(
            resolve_effective_device_id(Some("  heartbeat "), did).unwrap(),
            "heartbeat"
        );
        // Blank / unset fall back to the derived id.
        assert_eq!(resolve_effective_device_id(Some("   "), did).unwrap(), stable_device_id(did));
        assert_eq!(resolve_effective_device_id(None, did).unwrap(), stable_device_id(did));
        // Internal whitespace would be truncated by the whitespace-delimited
        // OAuth scope on the server side; it must be rejected loudly.
        assert!(resolve_effective_device_id(Some("my device"), did).is_err());
    }

    #[test]
    fn config_file_load_partial() {
        let dir = std::env::temp_dir().join("aqua-matrix-agent-test-partial");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        // Write a config with only client_id
        fs::write(&path, "[oidc]\nclient_id = \"partial-id\"\n").unwrap();
        let loaded = ConfigFile::load(&path).unwrap();
        assert_eq!(loaded.oidc.client_id.as_deref(), Some("partial-id"));
        assert!(loaded.oidc.redirect_uri.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- reauth_then_retry: the try -> reauth-once -> retry-once shape shared
    // by every `*_with_refresh` method (see the doc comment on the helper for
    // why these methods don't call it directly). ----

    #[tokio::test]
    async fn reauth_then_retry_reauths_once_on_unknown_token_then_succeeds() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let reauth_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let c = calls.clone();
        let rc = reauth_calls.clone();
        let result: Result<&'static str> = reauth_then_retry(
            move || {
                let c = c.clone();
                async move {
                    c.set(c.get() + 1);
                    if c.get() == 1 {
                        // Simulated M_UNKNOWN_TOKEN, shaped like the real matrix-sdk
                        // error string `is_unknown_token` matches against.
                        Err(anyhow!(
                            "the homeserver returned an error: M_UNKNOWN_TOKEN: Token is not active"
                        ))
                    } else {
                        Ok("delivered")
                    }
                }
            },
            move || {
                let rc = rc.clone();
                async move {
                    rc.set(rc.get() + 1);
                    Ok(())
                }
            },
        )
        .await;
        assert_eq!(result.unwrap(), "delivered");
        assert_eq!(calls.get(), 2, "op must run exactly twice: the failing try + the post-reauth retry");
        assert_eq!(reauth_calls.get(), 1, "reauth must run exactly once");
    }

    #[tokio::test]
    async fn reauth_then_retry_does_not_reauth_on_a_different_error() {
        // A non-token failure (e.g. a server 500) must propagate untouched — it
        // must NOT be misclassified as an auth problem and must NOT trigger a
        // reauth (which would mask the real fault and cost a token rotation for
        // nothing).
        let calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let reauth_calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let c = calls.clone();
        let rc = reauth_calls.clone();
        let result: Result<&'static str> = reauth_then_retry(
            move || {
                let c = c.clone();
                async move {
                    c.set(c.get() + 1);
                    Err(anyhow!("the homeserver returned an error: M_UNKNOWN (status_code: 500)"))
                }
            },
            move || {
                let rc = rc.clone();
                async move {
                    rc.set(rc.get() + 1);
                    Ok(())
                }
            },
        )
        .await;
        assert!(result.is_err(), "a non-token error must propagate");
        assert!(
            format!("{:#}", result.unwrap_err()).contains("M_UNKNOWN (status_code: 500)"),
            "the original error must pass through unwrapped, not be masked as a token issue"
        );
        assert_eq!(calls.get(), 1, "op must run exactly once: no retry on a non-token error");
        assert_eq!(reauth_calls.get(), 0, "a non-token error must never trigger a reauth");
    }

    #[tokio::test]
    async fn reauth_then_retry_propagates_a_failed_reauth_without_retrying_op() {
        // If the reauth itself fails (e.g. the refresh-grant call is down), that
        // failure must propagate — and `op` must NOT be tried a second time
        // against a token we just failed to refresh.
        let calls = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let c = calls.clone();
        let result: Result<&'static str> = reauth_then_retry(
            move || {
                let c = c.clone();
                async move {
                    c.set(c.get() + 1);
                    Err(anyhow!(
                        "the homeserver returned an error: M_UNKNOWN_TOKEN: Token is not active"
                    ))
                }
            },
            || async { Err(anyhow!("refresh-grant call failed: network unreachable")) },
        )
        .await;
        assert!(result.is_err(), "a reauth failure must propagate");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("token refresh after M_UNKNOWN_TOKEN failed"),
            "expected the reauth-failure context, got: {msg}"
        );
        assert!(msg.contains("network unreachable"), "expected the underlying cause, got: {msg}");
        assert_eq!(calls.get(), 1, "op must not be retried when reauth itself fails");
    }
}
