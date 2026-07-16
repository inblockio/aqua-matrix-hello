//! Element Call **media-encryption-key** transport for [`AgentClient`].
//!
//! ## Why this exists
//!
//! Element Call (and Element X) E2E-encrypts call **media** per participant with
//! AES-GCM frame encryption (separate from Megolm room encryption). Each
//! participant generates its own per-call AES key(s) and distributes them to
//! every *other* member device by sending an
//! `io.element.call.encryption_keys` event as an **Olm-encrypted to-device**
//! message. A peer that receives the key can decrypt that participant's media
//! frames; a participant that never publishes its key produces frames nobody
//! else can decode.
//!
//! For the agent's WebRTC media (in the sibling `../aqua-agents` call backend)
//! to interoperate with Element X, the agent must:
//!   1. **SEND** its own media keys, so Element X can decrypt the agent's frames
//!      ([`AgentClient::send_call_encryption_keys`]).
//!   2. **RECEIVE + decrypt** each peer's keys, so the agent can decrypt that
//!      peer's frames ([`AgentClient::on_call_encryption_keys`]).
//!
//! This module is the **Matrix transport only** — it carries the AES key bytes
//! over Olm to-device events. It contains no WebRTC and no frame cipher; the
//! call backend feeds the received keys into its LiveKit `KeyProvider` and hands
//! its own generated keys here to publish.
//!
//! ## Wire format (TWO shapes, both accepted on receive)
//!
//! Event type: `io.element.call.encryption_keys`. The decrypted to-device
//! content's `keys` field is **NOT** the same shape on every transport:
//!
//! * matrix-js-sdk / agent-to-agent (legacy here) sends an **array**:
//!   ```json
//!   { "keys": [ { "index": <u8>, "key": "<base64>" } ], "member": {...}, ... }
//!   ```
//! * Element X's `ToDeviceKeyTransport` sends `keys` as a **single object**
//!   (live failure: `invalid type: map, expected a sequence`):
//!   ```json
//!   { "keys": { "index": <u8>, "key": "<base64>" }, ... }
//!   ```
//!   and an index→key **map** (`{ "0": "<base64>" }`) is also tolerated.
//!
//! The lenient [`deserialize_keys`] below accepts all three and normalises to
//! `Vec<CallKey>`. The exact verbatim Element X content shape (the `member` /
//! `session` / any extra top-level fields) is **still unconfirmed** — it failed
//! to deserialize before any logging ran. The receive handler now ALWAYS
//! deserializes (member/session/extra are `serde_json::Value`) and logs the
//! verbatim content as pretty JSON, so the next live operator call reveals the
//! true shape from the `RX io.element.call.encryption_keys` banner.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
// `CollectStrategy` is the one type matrix-sdk takes but does not re-export; it
// lives in matrix-sdk-base's crypto module (a direct dep added for this).
use matrix_sdk_base::crypto::CollectStrategy;
use matrix_sdk::{
    encryption::identities::Device,
    ruma::{events::macros::EventContent, events::AnyToDeviceEventContent, serde::Raw, RoomId},
};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::mpsc;

use crate::AgentClient;

/// The unstable to-device event type Element Call uses to distribute per-call
/// AES media keys. Used as the wire `type` on both the send and receive paths.
pub const CALL_ENCRYPTION_KEYS_TYPE: &str = "io.element.call.encryption_keys";

// ---------------------------------------------------------------------------
// Wire content (serde, exact Element Call shape)
// ---------------------------------------------------------------------------

/// One AES media key for a participant: a key `index` (Element Call uses
/// `(i+1) % 256` as it ratchets) and the 16 random key bytes, base64-encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallKey {
    /// Key ring index this key occupies (frame trailer carries the same index).
    pub index: u8,
    /// Base64 of the 16 random AES key bytes.
    pub key: String,
}

/// Lenient deserializer for the `keys` field, accepting EVERY shape seen on the
/// wire and normalising to `Vec<CallKey>`. Without this, Element X's
/// single-object `keys` makes the whole typed to-device event fail to
/// deserialize (live: `invalid type: map, expected a sequence`), so the
/// handler body never runs and no key is ever installed.
///
/// Accepts:
/// * a JSON **array**            `[ {"index":N,"key":"b64"}, ... ]` (legacy / matrix-js-sdk)
/// * a single **object**         `{"index":N,"key":"b64"}`          (Element X to-device)
/// * an index→key **map**        `{"0":"b64","1":"b64"}`            (tolerated)
///
/// An empty/`null`/absent value yields an empty `Vec` (paired with
/// `#[serde(default)]`).
fn deserialize_keys<'de, D>(deserializer: D) -> std::result::Result<Vec<CallKey>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    use serde_json::Value;

    // Decode to a generic Value first, then branch on its runtime shape — this
    // is what lets one field accept three structurally different encodings.
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null => Ok(Vec::new()),
        // Already the canonical array of {index,key} objects.
        Value::Array(items) => items
            .into_iter()
            .map(|v| serde_json::from_value::<CallKey>(v).map_err(D::Error::custom))
            .collect(),
        Value::Object(map) => {
            // Disambiguate the two object shapes by looking for the `index`/`key`
            // keys of a single CallKey. If present, it's ONE key object; else
            // treat it as an index→base64-string map.
            if map.contains_key("index") || map.contains_key("key") {
                let single: CallKey =
                    serde_json::from_value(Value::Object(map)).map_err(D::Error::custom)?;
                Ok(vec![single])
            } else {
                let mut keys = Vec::with_capacity(map.len());
                for (idx_str, key_val) in map {
                    let index: u8 = idx_str.parse().map_err(|_| {
                        D::Error::custom(format!("call key map index not a u8: {idx_str:?}"))
                    })?;
                    let key = key_val.as_str().map(str::to_owned).ok_or_else(|| {
                        D::Error::custom(format!("call key map value not a string for index {index}"))
                    })?;
                    keys.push(CallKey { index, key });
                }
                // Stable order by index so callers see deterministic output.
                keys.sort_by_key(|k| k.index);
                Ok(keys)
            }
        }
        other => Err(D::Error::custom(format!(
            "call encryption keys: expected array, object, or null, got {other}"
        ))),
    }
}

/// Decrypted content of an `io.element.call.encryption_keys` to-device event.
///
/// The `#[ruma_event(type = ..., kind = ToDevice)]` derive generates the
/// `StaticEventContent` + `ToDeviceEventContent` impls matrix-sdk needs to
/// dispatch a typed `ToDeviceEvent<CallEncryptionKeysEventContent>` to an
/// `add_event_handler` closure (the receive path), and to render the wire JSON
/// for `encrypt_and_send_raw_to_device` (the send path). The derive also emits a
/// `CallEncryptionKeysEvent` type alias (`= ToDeviceEvent<…EventContent>`) — the
/// `…EventContent` ident is chosen so that stripped-suffix alias does NOT collide
/// with the public decoded [`CallEncryptionKeys`] struct below.
///
/// **Robustness over precision.** The verbatim Element X shape of `member` /
/// `session` / any other top-level fields is still unconfirmed (it failed to
/// deserialize before any logging), so those are kept as `serde_json::Value`
/// (and `extra` captures everything else) — this guarantees the content ALWAYS
/// deserializes and round-trips verbatim for the raw log in the handler.
/// `Eq` is dropped because `serde_json::Value` is not `Eq`.
#[derive(Clone, Debug, Serialize, Deserialize, EventContent)]
#[ruma_event(type = "io.element.call.encryption_keys", kind = ToDevice)]
pub struct CallEncryptionKeysEventContent {
    /// The participant's media keys. Parsed leniently (array / single object /
    /// index→key map) and normalised to a `Vec` (see [`deserialize_keys`]).
    #[serde(default, deserialize_with = "deserialize_keys")]
    pub keys: Vec<CallKey>,
    /// Who sent the keys — shape unknown, kept as raw JSON so it always parses
    /// and the device id can be probed from whatever keys it carries.
    #[serde(default)]
    pub member: serde_json::Value,
    /// The MatrixRTC session descriptor — shape unknown, kept as raw JSON.
    #[serde(default)]
    pub session: serde_json::Value,
    /// The Matrix room the call is in.
    #[serde(default)]
    pub room_id: String,
    /// Wall-clock send time in ms — used by Element Call to drop stale keys.
    #[serde(default)]
    pub sent_ts: u64,
    /// Any other top-level fields, captured verbatim so the raw log shows
    /// EVERYTHING Element X sends. If `flatten` ever conflicts with the
    /// `EventContent` derive this can be dropped (member/session already
    /// capture most of the content).
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Receive-side surfaced type (decoded, ready for the LiveKit KeyProvider)
// ---------------------------------------------------------------------------

/// A decoded inbound media-key set, surfaced to the call backend. The base64 is
/// already decoded into raw key bytes so the consumer can hand each
/// `(index, bytes)` straight to a LiveKit `KeyProvider::set_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallEncryptionKeys {
    /// The to-device event sender's Matrix user id (decrypted-event `sender`).
    pub sender_user_id: String,
    /// The sender's device id. Extracted best-effort from the content: from
    /// `member.claimed_device_id` / `member.device_id`, else parsed from
    /// `membershipID` (`"<user>:<device>"`, take after the LAST `:`), else from
    /// any `device_id`/`membershipID` in the extra top-level fields. The LiveKit
    /// participant identity is `<sender_user_id>:<sender_device_id>`, so the
    /// call backend installs this peer's key under that identity.
    pub sender_device_id: String,
    /// The room the call is in (content `room_id`).
    pub room_id: String,
    /// `(index, key_bytes)` pairs — base64 already decoded.
    pub keys: Vec<(u8, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Minimal, dependency-free base64 (standard alphabet, with padding)
// ---------------------------------------------------------------------------
//
// The connector deliberately pulls in no `base64` crate for one tiny codec.
// Element Call emits standard-alphabet base64 *with* padding for the 16 key
// bytes; we encode the same and decode tolerantly (accept missing padding).

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    // Collect significant symbols (ignore '=' padding and any whitespace).
    let syms: Vec<u32> = input
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .map(|c| b64_val(c).ok_or_else(|| anyhow!("invalid base64 byte: {c:#x}")))
        .collect::<Result<_>>()?;

    let mut out = Vec::with_capacity(syms.len() * 3 / 4);
    for chunk in syms.chunks(4) {
        match chunk.len() {
            // A lone symbol can't form a byte — malformed.
            1 => return Err(anyhow!("invalid base64 length")),
            2 => {
                let n = (chunk[0] << 18) | (chunk[1] << 12);
                out.push((n >> 16) as u8);
            }
            3 => {
                let n = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            _ => {
                let n = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
        }
    }
    Ok(out)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pure builder for the pre-Olm `io.element.call.encryption_keys` JSON body.
///
/// Wire shape MUST match matrix-js-sdk `ToDeviceKeyTransport.sendKey` +
/// `getValidEventContent` (Element Call / Element X / Element Web):
///
/// - `keys` is a **single object** `{ index, key }` — NOT an array. Element
///   checks `content.keys.key` and drops arrays as "Malformed Event: Missing
///   keys field" → grey empty tile + silence while we still decrypt *their*
///   frames (asymmetric failure).
/// - `member.id` = `${user}:${device}` (Element's receive fallback).
/// - No top-level `device_id` / `membershipID` (Element does not send them).
///
/// Extracted so unit tests lock the production path (not a hand-copied fixture).
pub fn build_call_encryption_keys_content(
    room_id: &str,
    own_user: &str,
    device_id: &str,
    key_index: u8,
    key: &[u8],
    sent_ts_ms: u64,
) -> serde_json::Value {
    let membership_id = format!("{own_user}:{device_id}");
    serde_json::json!({
        "keys": { "index": key_index, "key": base64_encode(key) },
        "member": {
            "claimed_device_id": device_id,
            "id": membership_id,
        },
        "session": { "application": "m.call", "call_id": "", "scope": "m.room" },
        "room_id": room_id,
        "sent_ts": sent_ts_ms,
    })
}

/// Element-side validation of an encryption_keys payload (mirrors
/// `ToDeviceKeyTransport.getValidEventContent`). Returns `Ok(())` only when
/// Element would accept and install the key.
pub fn element_call_accepts_encryption_keys(content: &serde_json::Value) -> Result<(), &'static str> {
    let room_id = content.get("room_id").and_then(|v| v.as_str());
    if room_id.map(|s| s.is_empty()).unwrap_or(true) {
        return Err("no room_id");
    }
    let keys = content.get("keys").ok_or("missing keys")?;
    if !keys.is_object() {
        return Err("keys must be a single object (not array/null)");
    }
    if keys.get("key").and_then(|v| v.as_str()).map(|s| s.is_empty()).unwrap_or(true) {
        return Err("Missing keys field (keys.key)");
    }
    if keys.get("index").and_then(|v| v.as_u64()).is_none() {
        return Err("Missing keys field (keys.index)");
    }
    let member = content.get("member").ok_or("missing member")?;
    if member
        .get("claimed_device_id")
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        return Err("Missing claimed_device_id");
    }
    Ok(())
}

/// Pull a string field out of a `serde_json::Value` object by key (None unless
/// it's an object with that key holding a non-empty string).
fn json_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

/// A `membershipID` is `"<user_id>:<device_id>"`; the device id is everything
/// after the LAST `:` (user ids themselves contain a `:` before the homeserver,
/// so we must split from the right). Returns None if there's no `:` or the tail
/// is empty.
fn device_from_membership_id(membership_id: &str) -> Option<String> {
    membership_id
        .rsplit_once(':')
        .map(|(_, dev)| dev.to_owned())
        .filter(|d| !d.is_empty())
}

/// Best-effort extraction of the sender's Matrix device id from the (unconfirmed)
/// Element X content. Tried in order:
///   1. `member.claimed_device_id`, then `member.device_id`
///   2. `member.membershipID` parsed as `"<user>:<device>"`
///   3. top-level (extra) `device_id`, then `membershipID`
///
/// The to-device event itself carries no device id (`ToDeviceEvent` exposes only
/// `sender` + `content`), so there is no event-level fallback. Returns None if
/// nothing matched (the caller logs a warning and uses an empty id).
fn extract_sender_device_id(content: &CallEncryptionKeysEventContent) -> Option<String> {
    // 1 + 2: probe the member object (whatever shape it turns out to be).
    json_str(&content.member, "claimed_device_id")
        .or_else(|| json_str(&content.member, "device_id"))
        .or_else(|| {
            content
                .member
                .get("membershipID")
                .and_then(|v| v.as_str())
                .and_then(device_from_membership_id)
        })
        // 3: top-level fields captured by `extra`.
        .or_else(|| {
            content
                .extra
                .get("device_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            content
                .extra
                .get("membershipID")
                .and_then(|v| v.as_str())
                .and_then(device_from_membership_id)
        })
}

// ---------------------------------------------------------------------------
// AgentClient API: send + receive
// ---------------------------------------------------------------------------

impl AgentClient {
    /// Olm-encrypt and send this agent's media key for `room_id` to **every
    /// device of every other member** of the room — the Element Call key-share.
    ///
    /// `key_index` is the key-ring slot (Element Call ratchets `(i+1) % 256`);
    /// `key` is the raw 16 AES key bytes (base64-encoded here for the wire).
    ///
    /// **Wire shape mirrors matrix-js-sdk `ToDeviceKeyTransport`.** `keys` is a
    /// SINGLE OBJECT `{"index":N,"key":"b64"}` (NOT an array — Element rejects
    /// arrays as "Malformed Event: Missing keys field"). `member.claimed_device_id`
    /// identifies our device; top-level `device_id`/`membershipID` are defensive
    /// extras. `session` is the room-scoped `m.call` default; `sent_ts` is now.
    /// Our receive path still accepts array|object|map so agent-to-agent and
    /// Element both work inbound.
    ///
    /// Recipients are collected as all devices of all joined room members
    /// *except this agent's own user id*. Sent with
    /// [`CollectStrategy::AllDevices`] so it reaches **unverified** Element X
    /// devices too (we never cross-sign-verify a human's device, so a
    /// verification-gated strategy would silently withhold the key and break
    /// media). Returns `Ok(())` even if `encrypt_and_send_raw_to_device`
    /// reports per-device failures (logged) — a single unreachable device must
    /// not abort the whole share; it errors only if the content can't be built
    /// or no recipient devices exist.
    pub async fn send_call_encryption_keys(
        &self,
        room_id: &str,
        key_index: u8,
        key: &[u8],
    ) -> Result<()> {
        let own_user = self.user_id().to_owned();
        let device_id = self
            .device_id()
            .ok_or_else(|| anyhow!("agent has no device_id; cannot send call encryption keys"))?;

        let content = build_call_encryption_keys_content(
            room_id,
            &own_user,
            &device_id,
            key_index,
            key,
            now_ms(),
        );
        let membership_id = format!("{own_user}:{device_id}");
        tracing::info!(
            room_id,
            key_index,
            claimed_device_id = %device_id,
            member_id = %membership_id,
            keys_is_object = content.get("keys").map(|k| k.is_object()).unwrap_or(false),
            "TX io.element.call.encryption_keys wire shape (pre-Olm)"
        );

        // Collect every device of every OTHER joined room member. `Device`s come
        // from the crypto store (populated by sync); we own them in `devices`
        // and pass borrows to the send call.
        let devices = self.other_member_devices(room_id, &own_user).await?;
        if devices.is_empty() {
            return Err(anyhow!(
                "no recipient devices for call encryption keys in {room_id} \
                 (no other members, or their devices not yet synced)"
            ));
        }
        let device_refs: Vec<&Device> = devices.iter().collect();

        // Raw<AnyToDeviceEventContent>: serialize our typed content to JSON then
        // re-tag it as the generic to-device-content the API takes (same pattern
        // as `update_registry`'s account-data raw cast). matrix-sdk Olm-encrypts
        // this per recipient device.
        let raw: Raw<AnyToDeviceEventContent> = Raw::new(&content)
            .context("failed to serialize call encryption keys content")?
            .cast_unchecked();

        let failures = self
            .client()
            .encryption()
            .encrypt_and_send_raw_to_device(
                device_refs,
                CALL_ENCRYPTION_KEYS_TYPE,
                raw,
                CollectStrategy::AllDevices,
            )
            .await
            .context("encrypt_and_send_raw_to_device failed")?;

        if failures.is_empty() {
            tracing::info!(
                room_id,
                key_index,
                recipients = devices.len(),
                "sent call encryption keys to all recipient devices"
            );
        } else {
            tracing::warn!(
                room_id,
                key_index,
                recipients = devices.len(),
                failed = failures.len(),
                "sent call encryption keys; some recipient devices failed (withheld/unreachable): {failures:?}"
            );
        }
        Ok(())
    }

    /// Gather every [`Device`] of every joined member of `room_id` *except*
    /// `own_user`'s devices. Best-effort per user: a user whose devices haven't
    /// synced yet contributes none (logged), rather than failing the whole set.
    async fn other_member_devices(
        &self,
        room_id: &str,
        own_user: &str,
    ) -> Result<Vec<Device>> {
        use matrix_sdk::RoomMemberships;

        let room_id: &RoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        let room = self
            .client()
            .get_room(room_id)
            .ok_or_else(|| anyhow!("room {room_id} not found / not joined"))?;

        let members = room
            .members(RoomMemberships::JOIN)
            .await
            .context("failed to list joined room members")?;

        let mut devices = Vec::new();
        for member in members {
            let uid = member.user_id();
            if uid.as_str() == own_user {
                continue;
            }
            match self.client().encryption().get_user_devices(uid).await {
                Ok(user_devices) => {
                    for d in user_devices.devices() {
                        devices.push(d);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        user_id = %uid,
                        "failed to list devices for room member; skipping: {e:#}"
                    );
                }
            }
        }
        Ok(devices)
    }

    /// Register a to-device handler for incoming `io.element.call.encryption_keys`
    /// and return the receiving end of a channel that yields each decrypted,
    /// base64-decoded [`CallEncryptionKeys`].
    ///
    /// matrix-sdk decrypts Olm to-device events during `client.sync(...)` and
    /// dispatches them to handlers registered via `add_event_handler`. The
    /// `#[ruma_event(kind = ToDevice)]` derive lets us register a **typed**
    /// `ToDeviceEvent<CallEncryptionKeysEventContent>` handler, which only fires for
    /// our event type and hands us already-deserialized content. (No
    /// `EncryptionInfo` arg is requested here; the call backend trusts the
    /// `member` fields for identity, matching matrix-js-sdk's transport.)
    ///
    /// The handler is driven by whatever `sync` loop is running on this client
    /// (e.g. the relay's `run_daemon` sync task) — call this **after** connect
    /// and while a sync is (or will be) active. The returned `Receiver` lives in
    /// the caller's event loop; the channel is unbounded-ish (`capacity`), and
    /// keys are dropped (logged) if the consumer falls behind.
    ///
    /// Returns a `Receiver`; keeping it alive keeps the handler useful (dropping
    /// it just makes sends no-op — the handler stays registered but discards).
    pub fn on_call_encryption_keys(&self, capacity: usize) -> mpsc::Receiver<CallEncryptionKeys> {
        use matrix_sdk::ruma::events::ToDeviceEvent;

        let (tx, rx) = mpsc::channel(capacity.max(1));
        self.client().add_event_handler(
            move |ev: ToDeviceEvent<CallEncryptionKeysEventContent>| {
                let tx = tx.clone();
                async move {
                    let sender_user_id = ev.sender.to_string();
                    let content = ev.content;

                    // GROUND TRUTH: log the verbatim content as pretty JSON. The
                    // Element X to-device shape is still unconfirmed (it failed to
                    // deserialize before any logging ran); member/session/extra are
                    // raw `Value`, so this round-trips EVERYTHING Element X sent.
                    // This is the line the next live operator call will reveal the
                    // true shape from.
                    match serde_json::to_string_pretty(&content) {
                        Ok(pretty) => tracing::info!(
                            sender = %sender_user_id,
                            "RX io.element.call.encryption_keys (verbatim content):\n{pretty}"
                        ),
                        Err(e) => tracing::info!(
                            sender = %sender_user_id,
                            "RX io.element.call.encryption_keys (content not re-serializable: {e:#})"
                        ),
                    }

                    // Extract the sender device id best-effort. The LiveKit
                    // participant identity is `<sender_user_id>:<sender_device_id>`,
                    // so the backend must install this key under THAT identity.
                    let sender_device_id =
                        extract_sender_device_id(&content).unwrap_or_else(|| {
                            tracing::warn!(
                                sender = %sender_user_id,
                                "could not determine sender device id for call \
                                 encryption keys; key may install under wrong \
                                 LiveKit identity"
                            );
                            String::new()
                        });

                    // Decode each base64 key; skip (and log) any that don't decode
                    // rather than dropping the whole event.
                    let mut keys = Vec::with_capacity(content.keys.len());
                    for k in &content.keys {
                        match base64_decode(&k.key) {
                            Ok(bytes) => keys.push((k.index, bytes)),
                            Err(e) => tracing::warn!(
                                sender = %sender_user_id,
                                index = k.index,
                                "dropping undecodable call encryption key: {e:#}"
                            ),
                        }
                    }

                    // Prefer the content's own room_id; fall back is left to the
                    // caller (the to-device event carries no room).
                    let room_id = content.room_id.clone();

                    let decoded = CallEncryptionKeys {
                        sender_user_id,
                        sender_device_id,
                        room_id,
                        keys,
                    };

                    // `try_send`: never block the sync dispatch loop. A full
                    // channel means the consumer is behind — drop + log.
                    if let Err(e) = tx.try_send(decoded) {
                        tracing::warn!("call encryption keys receiver lagging; dropped event: {e}");
                    }
                }
            },
        );
        rx
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn base64_roundtrip_and_known_vectors() {
        // Known vectors against the standard alphabet (with padding).
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");

        // 16-byte key (the Element Call media-key length) round-trips.
        let key: Vec<u8> = (0u8..16).collect();
        let encoded = base64_encode(&key);
        assert_eq!(base64_decode(&encoded).unwrap(), key);

        // Tolerant decode: missing padding still works.
        assert_eq!(base64_decode("Zm9vYg").unwrap(), b"foob");
    }

    /// 16 random-looking bytes -> the base64 a real payload carries.
    fn sample_key() -> (Vec<u8>, String) {
        let key_bytes: Vec<u8> = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key_b64 = base64_encode(&key_bytes);
        (key_bytes, key_b64)
    }

    /// Deserialize the legacy / matrix-js-sdk wire shape (`keys` as an ARRAY)
    /// into the typed content, proving the array path still works and member /
    /// session round-trip verbatim as raw JSON.
    #[test]
    fn keys_array_shape_deserializes() {
        let (key_bytes, key_b64) = sample_key();

        let wire = json!({
            "keys": [ { "index": 1, "key": key_b64 } ],
            "member": {
                "id": "@agent:matrix.inblock.io",
                "claimed_device_id": "ABCDEFGHIJ"
            },
            "session": {
                "call_id": "",
                "application": "m.call",
                "scope": "m.room"
            },
            "room_id": "!room:matrix.inblock.io",
            "sent_ts": 1_733_000_000_000u64
        });

        let content: CallEncryptionKeysEventContent =
            serde_json::from_value(wire).expect("array wire JSON should deserialize");

        assert_eq!(content.keys.len(), 1);
        assert_eq!(content.keys[0].index, 1);
        assert_eq!(content.keys[0].key, key_b64);
        assert_eq!(base64_decode(&content.keys[0].key).unwrap(), key_bytes);
        // member/session round-trip as raw JSON.
        assert_eq!(content.member["claimed_device_id"], "ABCDEFGHIJ");
        assert_eq!(content.session["application"], "m.call");
        assert_eq!(content.room_id, "!room:matrix.inblock.io");
        assert_eq!(content.sent_ts, 1_733_000_000_000u64);
        // Device extraction from member.claimed_device_id.
        assert_eq!(extract_sender_device_id(&content).as_deref(), Some("ABCDEFGHIJ"));
    }

    /// THE BUG FIX: Element X's to-device transport sends `keys` as a SINGLE
    /// OBJECT (a JSON map), which previously failed to deserialize (`invalid
    /// type: map, expected a sequence`). It must now deserialize to the SAME
    /// single-element `Vec<CallKey>` as the array shape.
    #[test]
    fn keys_single_object_shape_deserializes() {
        let (key_bytes, key_b64) = sample_key();

        let wire = json!({
            // Element X: keys is ONE object, not an array.
            "keys": { "index": 1, "key": key_b64 },
            "member": { "id": "@x:matrix.inblock.io" },
            "room_id": "!room:matrix.inblock.io",
            "sent_ts": 1u64
        });

        let content: CallEncryptionKeysEventContent =
            serde_json::from_value(wire).expect("single-object wire JSON should deserialize");

        assert_eq!(content.keys.len(), 1, "single object → one CallKey");
        assert_eq!(content.keys[0].index, 1);
        assert_eq!(base64_decode(&content.keys[0].key).unwrap(), key_bytes);
    }

    /// Both wire shapes normalise to the identical `Vec<CallKey>`.
    #[test]
    fn array_and_single_object_yield_same_keys() {
        let (_bytes, key_b64) = sample_key();

        let from_array: CallEncryptionKeysEventContent = serde_json::from_value(json!({
            "keys": [ { "index": 7, "key": key_b64 } ],
        }))
        .unwrap();
        let from_object: CallEncryptionKeysEventContent = serde_json::from_value(json!({
            "keys": { "index": 7, "key": key_b64 },
        }))
        .unwrap();

        assert_eq!(from_array.keys, from_object.keys);
        assert_eq!(from_array.keys.len(), 1);
        assert_eq!(from_array.keys[0].index, 7);
    }

    /// The index→key MAP shape (`{"0":"b64","1":"b64"}`) is also tolerated,
    /// normalised to `Vec<CallKey>` ordered by index.
    #[test]
    fn keys_index_map_shape_deserializes() {
        let (_bytes, key_b64) = sample_key();
        let other_b64 = base64_encode(b"sixteen-byte-key");

        let content: CallEncryptionKeysEventContent = serde_json::from_value(json!({
            "keys": { "1": other_b64, "0": key_b64 },
        }))
        .unwrap();

        assert_eq!(content.keys.len(), 2);
        // Sorted by index.
        assert_eq!(content.keys[0].index, 0);
        assert_eq!(content.keys[0].key, key_b64);
        assert_eq!(content.keys[1].index, 1);
        assert_eq!(content.keys[1].key, other_b64);
    }

    /// Absent / null / empty `keys` yields an empty Vec (the handler still runs
    /// and logs, rather than failing the whole event).
    #[test]
    fn keys_absent_or_empty_yields_empty_vec() {
        for wire in [json!({}), json!({ "keys": null }), json!({ "keys": [] })] {
            let content: CallEncryptionKeysEventContent =
                serde_json::from_value(wire).expect("lenient keys should accept empty");
            assert!(content.keys.is_empty());
        }
    }

    /// Production builder (`build_call_encryption_keys_content`) must emit the
    /// matrix-js-sdk ToDeviceKeyTransport shape. Element drops array `keys` as
    /// "Malformed Event: Missing keys field" → grey empty tile (2026-07-16).
    #[test]
    fn send_side_emits_keys_as_single_object_matching_element_call() {
        let (key_bytes, key_b64) = sample_key();
        let own_user = "@agent:matrix.inblock.io";
        let device_id = "ABCDEFGHIJ";
        let room = "!room:matrix.inblock.io";
        let membership_id = format!("{own_user}:{device_id}");

        let content =
            build_call_encryption_keys_content(room, own_user, device_id, 3, &key_bytes, 1);

        assert!(
            element_call_accepts_encryption_keys(&content).is_ok(),
            "Element getValidEventContent must accept: {:?}",
            element_call_accepts_encryption_keys(&content)
        );
        assert!(content["keys"].is_object(), "send must emit keys as a single object");
        assert!(!content["keys"].is_array());
        assert_eq!(content["keys"]["index"], 3);
        assert_eq!(content["keys"]["key"], key_b64);
        assert_eq!(content["member"]["claimed_device_id"], device_id);
        assert_eq!(content["member"]["id"], membership_id);
        assert_eq!(content["room_id"], room);
        // Element ToDeviceKeyTransport does not put these top-level.
        assert!(content.get("device_id").is_none());
        assert!(content.get("membershipID").is_none());

        // Our own permissive receiver still parses it back to one CallKey.
        let parsed: CallEncryptionKeysEventContent =
            serde_json::from_value(content).expect("our receiver accepts our own send shape");
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].index, 3);
        assert_eq!(extract_sender_device_id(&parsed).as_deref(), Some(device_id));
    }

    /// Regression: array-shaped `keys` is what Element Call rejects (grey tile).
    /// The production builder must never emit this; the validator must refuse it.
    #[test]
    fn element_call_rejects_array_keys_shape() {
        let (key_bytes, key_b64) = sample_key();
        let malformed = json!({
            "keys": [ { "index": 0, "key": key_b64 } ],
            "member": { "claimed_device_id": "DEV", "id": "@u:hs:DEV" },
            "session": { "application": "m.call", "call_id": "", "scope": "m.room" },
            "room_id": "!r:hs",
            "sent_ts": 1u64,
        });
        assert_eq!(
            element_call_accepts_encryption_keys(&malformed),
            Err("keys must be a single object (not array/null)")
        );
        // And the good builder never produces that.
        let good = build_call_encryption_keys_content("!r:hs", "@u:hs", "DEV", 0, &key_bytes, 1);
        assert!(element_call_accepts_encryption_keys(&good).is_ok());
        assert!(good["keys"].is_object());
    }

    /// member.id must be user:device (LiveKit identity / Element fallback), not
    /// bare mxid — hashed RTC identities and delayed-key membership matching
    /// depend on consistent memberId.
    #[test]
    fn member_id_is_user_colon_device_not_bare_mxid() {
        let (key_bytes, _) = sample_key();
        let user = "@did-key-z6mkmwzijj2k3ckqvqnmmgvkefmhdse4zxrfvqksxdmgba4v:matrix.inblock.io";
        let dev = "SIWX_4137b749";
        let content =
            build_call_encryption_keys_content("!bNDjt:matrix.inblock.io", user, dev, 0, &key_bytes, 42);
        assert_eq!(
            content["member"]["id"].as_str().unwrap(),
            format!("{user}:{dev}")
        );
        assert_ne!(content["member"]["id"].as_str().unwrap(), user);
    }

    /// Device-id extraction fallbacks: member.device_id, membershipID parsing
    /// (split on the LAST colon, since user ids contain a colon), and the
    /// top-level (extra) `device_id` / `membershipID`.
    #[test]
    fn device_id_extraction_fallbacks() {
        // member.device_id (not claimed_device_id)
        let c: CallEncryptionKeysEventContent =
            serde_json::from_value(json!({ "member": { "device_id": "DEV1" } })).unwrap();
        assert_eq!(extract_sender_device_id(&c).as_deref(), Some("DEV1"));

        // member.membershipID "<user>:<device>" — device is after the LAST ':'.
        let c: CallEncryptionKeysEventContent = serde_json::from_value(json!({
            "member": { "membershipID": "@did-pkh-eip155:1:0xABC:6zqlNZdevicekey" }
        }))
        .unwrap();
        assert_eq!(extract_sender_device_id(&c).as_deref(), Some("6zqlNZdevicekey"));

        // top-level device_id (captured by `extra`)
        let c: CallEncryptionKeysEventContent =
            serde_json::from_value(json!({ "device_id": "TOPLEVELDEV" })).unwrap();
        assert_eq!(extract_sender_device_id(&c).as_deref(), Some("TOPLEVELDEV"));

        // top-level membershipID (captured by `extra`)
        let c: CallEncryptionKeysEventContent =
            serde_json::from_value(json!({ "membershipID": "@u:hs.tld:TOPDEV" })).unwrap();
        assert_eq!(extract_sender_device_id(&c).as_deref(), Some("TOPDEV"));

        // nothing → None (handler logs a warning and uses empty id)
        let c: CallEncryptionKeysEventContent = serde_json::from_value(json!({})).unwrap();
        assert_eq!(extract_sender_device_id(&c), None);
    }

    /// The derive must wire the unstable event type through `StaticEventContent`
    /// so the typed to-device handler dispatches on the right `type`.
    #[test]
    fn event_type_matches_element_call() {
        use matrix_sdk::ruma::events::StaticEventContent;
        assert_eq!(
            <CallEncryptionKeysEventContent as StaticEventContent>::TYPE,
            CALL_ENCRYPTION_KEYS_TYPE
        );
        assert_eq!(CALL_ENCRYPTION_KEYS_TYPE, "io.element.call.encryption_keys");
    }
}
