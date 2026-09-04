//! Call **signaling** for [`AgentClient`].
//!
//! ## Scope: signaling, not media
//!
//! matrix-sdk 0.17 ships no WebRTC/LiveKit media stack, so an agent can *ring* a
//! peer and *observe* call events, but it cannot place or carry the actual
//! audio/video stream of a call. [`ring_call`](AgentClient::ring_call) emits the
//! same `m.call.notify` (MSC4075) signal Element Call uses to make a peer's
//! Element X show an incoming call; joining the media would need an embedded
//! WebRTC engine (a separate, much larger effort). Inbound call *detection* is
//! surfaced through the relay's `on_call` seam.
//!
//! `m.call.notify` / `ApplicationType` are deprecated in ruma in favour of
//! `m.rtc.notification`, but they remain what current Element clients emit and
//! honour, so this module uses them deliberately — hence the module-wide
//! `allow(deprecated)`.
#![allow(deprecated)]

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use matrix_sdk::ruma::events::call::member::{
    ActiveFocus, ActiveLivekitFocus, Application, CallApplicationContent, CallMemberEventContent,
    CallMemberStateKey, CallScope, Focus, LivekitFocus,
};
use matrix_sdk::ruma::events::call::notify::{ApplicationType, CallNotifyEventContent};
use matrix_sdk::ruma::events::rtc::notification::NotificationType;
use matrix_sdk::ruma::events::Mentions;
use matrix_sdk::ruma::{OwnedUserId, RoomId, UserId};

use crate::AgentClient;

/// The deployment default MatrixRTC focus (LiveKit JWT service) for this stack.
/// Used when the homeserver `.well-known` advertises no `org.matrix.msc4143.rtc_foci`.
pub const DEFAULT_LIVEKIT_SERVICE_URL: &str = "https://matrix.inblock.io/livekit/jwt";

impl AgentClient {
    /// Ring `target`: send an `m.call.notify` (MSC4075) with `NotificationType::Ring`
    /// into the DM, mentioning the peer — the same event Element Call emits to make
    /// a recipient's Element X show an incoming call.
    ///
    /// **Best-effort SIGNALING only.** This announces/rings a call; it does NOT
    /// open a media stream (matrix-sdk has no WebRTC). Whether a given client
    /// surfaces a ring with no accompanying MatrixRTC session is up to the client.
    /// Returns the event id of the notify.
    pub async fn ring_call(&self, target: &str) -> Result<String> {
        let user: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid target: {e}"))?;
        let room = self.ensure_dm_room(user).await?;
        let content = CallNotifyEventContent::new(
            new_call_id(),
            ApplicationType::Call,
            NotificationType::Ring,
            Mentions::with_user_ids([user.to_owned()]),
        );
        let resp = room
            .send(content)
            .await
            .context("failed to send call ring")?;
        Ok(resp.response.event_id.to_string())
    }
}

impl AgentClient {
    /// Request a Matrix **OpenID token** (`POST /user/{id}/openid/request_token`),
    /// returned as the JSON object an Element Call / `lk-jwt-service` expects in
    /// its `openid_token` field. This is the credential a MatrixRTC focus
    /// (LiveKit JWT service) exchanges — together with the room id and
    /// [`device_id`](AgentClient::device_id) — for a LiveKit access token at
    /// `POST {rtc_foci.livekit_service_url}/sfu/get`. The connector deliberately
    /// stops here (token minting is a Matrix-session operation); the LiveKit
    /// connection + media live in the agents-side call backend.
    pub async fn request_openid_token(&self) -> Result<serde_json::Value> {
        let resp = self
            .client()
            .account()
            .request_openid_token()
            .await
            .context("openid request_token failed")?;
        Ok(serde_json::json!({
            "access_token": resp.access_token,
            "token_type": resp.token_type,
            "matrix_server_name": resp.matrix_server_name,
            "expires_in": resp.expires_in.as_secs(),
        }))
    }
}

impl AgentClient {
    /// Resolve a joined [`matrix_sdk::Room`] by id, or error if this agent is
    /// not in it. Membership state can only be written to a room we have joined.
    fn rtc_room(&self, room_id: &str) -> Result<matrix_sdk::Room> {
        let room_id: &RoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        self.client()
            .get_room(room_id)
            .ok_or_else(|| anyhow!("room {room_id} not found / not joined"))
    }

    /// Build the MSC3401 call-member state key for THIS user+device, matching
    /// the format the deployed Element Call (`call.element.io`) actually writes.
    ///
    /// Ground truth from the live Element Call JS bundle (and matrix-js-sdk
    /// `MatrixRTCSession.makeMembershipStateKey`, cross-checked against ruma's
    /// own `CallMemberStateKey` doc example `_@test:user.org_DEVICE_m.call`):
    /// the key is **`_{user_id}_{device_id}_m.call`** — i.e. the `member_id`
    /// segment is `{device_id}_{application}` (`m.call`), NOT the bare device id.
    /// The **leading underscore** is the MSC3757 "owned state event" marker that
    /// lets the sender set a state key embedding its own `@user` mxid; servers
    /// without MSC3757 reject it, so [`set_rtc_member`](Self::set_rtc_member)
    /// falls back to the unprefixed `{user_id}_{device_id}_m.call`.
    fn rtc_member_state_key(&self, underscore: bool) -> Result<CallMemberStateKey> {
        let user_id: OwnedUserId = self
            .user_id()
            .try_into()
            .map_err(|e| anyhow!("agent has an invalid user_id: {e}"))?;
        let device_id = self
            .device_id()
            .ok_or_else(|| anyhow!("agent has no device_id; cannot set RTC membership"))?;
        // member_id = `{device_id}_m.call` (device + application), per the
        // deployed Element Call. ruma renders the key as `_{user}_{member_id}`.
        let member_id = format!("{device_id}_m.call");
        Ok(CallMemberStateKey::new(
            user_id,
            Some(member_id),
            underscore,
        ))
    }

    /// Publish this agent's **MatrixRTC membership** (`org.matrix.msc3401.call.member`)
    /// into `room_id`, so Element X / Element Call discovers the agent as a call
    /// participant. This is the Matrix-signaling counterpart to the agents-side
    /// LiveKit media join: the media plane proves the agent is *in* the SFU room,
    /// this state event is what makes a human's client *show* it.
    ///
    /// Builds a [`SessionMembershipData`](matrix_sdk::ruma::events::call::member::SessionMembershipData)
    /// with `application=m.call`, `call_id=""` (room-scoped), `scope=m.room`,
    /// this device's `device_id`, a LiveKit `focus_active`
    /// (`focus_selection=oldest_membership`) and a single `foci_preferred`
    /// LiveKit focus carrying `livekit_alias` + `livekit_service_url`. The default
    /// 4-hour membership expiry is left in place (no refresh — see the long-call
    /// TODO below). `livekit_alias` should be the same `room_id` string the
    /// lk-jwt handshake uses as its `room` param so the agent and Element X derive
    /// the same LiveKit room.
    ///
    /// Sent with the MSC3757 owned-state key (`_{user}_{device}`). If the
    /// homeserver lacks MSC3757 support it rejects the leading underscore with
    /// `M_FORBIDDEN`; we then transparently retry with the unprefixed key
    /// (`{user}_{device}`) and log which form the server accepted.
    ///
    /// TODO(long-presence): the membership expires after 4h by default. A call
    /// held open longer than that needs the event re-sent before expiry (copying
    /// the original `created_ts`); short calls need no refresh.
    pub async fn set_rtc_member(
        &self,
        room_id: &str,
        livekit_alias: &str,
        livekit_service_url: &str,
    ) -> Result<()> {
        let room = self.rtc_room(room_id)?;
        let device_id = self
            .device_id()
            .ok_or_else(|| anyhow!("agent has no device_id; cannot set RTC membership"))?;

        let content = CallMemberEventContent::new(
            Application::Call(CallApplicationContent::new(String::new(), CallScope::Room)),
            device_id.as_str().into(),
            ActiveFocus::Livekit(ActiveLivekitFocus::new()),
            vec![Focus::Livekit(LivekitFocus::new(
                livekit_alias.to_owned(),
                livekit_service_url.to_owned(),
            ))],
            // Initial join: created_ts is unknown client-side; the homeserver's
            // origin_server_ts becomes the effective creation time.
            None,
            // None -> ruma defaults to the 4h Element Call membership expiry.
            None,
        );

        // Prefer the MSC3757 owned-state key (leading underscore). Fall back to
        // the unprefixed key if the server rejects owned state events.
        let owned_key = self.rtc_member_state_key(true)?;
        match room
            .send_state_event_for_key(&owned_key, content.clone())
            .await
        {
            Ok(resp) => {
                tracing::info!(
                    state_key = owned_key.as_ref(),
                    event_id = %resp.event_id,
                    "set RTC membership (MSC3757 owned state key accepted)"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "owned (underscore) RTC member state key rejected; retrying unprefixed (no MSC3757)"
                );
                let plain_key = self.rtc_member_state_key(false)?;
                let resp = room
                    .send_state_event_for_key(&plain_key, content)
                    .await
                    .context("failed to set RTC membership (both owned and plain state keys)")?;
                tracing::info!(
                    state_key = plain_key.as_ref(),
                    event_id = %resp.event_id,
                    "set RTC membership (unprefixed state key accepted; server lacks MSC3757)"
                );
                Ok(())
            }
        }
    }

    /// Clear this agent's MatrixRTC membership in `room_id` — the "left the call"
    /// state. Sends an **empty** `org.matrix.msc3401.call.member` content
    /// ([`CallMemberEventContent::new_empty(None)`]) to the same owned state key,
    /// which Element Call reads as the device having disconnected.
    ///
    /// Tries the owned (underscore) key first to match [`set_rtc_member`], then
    /// the unprefixed key, so whichever form the join used gets cleared.
    pub async fn clear_rtc_member(&self, room_id: &str) -> Result<()> {
        let room = self.rtc_room(room_id)?;
        let empty = CallMemberEventContent::new_empty(None);

        let owned_key = self.rtc_member_state_key(true)?;
        match room
            .send_state_event_for_key(&owned_key, empty.clone())
            .await
        {
            Ok(resp) => {
                tracing::info!(
                    state_key = owned_key.as_ref(),
                    event_id = %resp.event_id,
                    "cleared RTC membership (owned state key)"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "owned (underscore) RTC member clear rejected; retrying unprefixed"
                );
                let plain_key = self.rtc_member_state_key(false)?;
                let resp = room
                    .send_state_event_for_key(&plain_key, empty)
                    .await
                    .context("failed to clear RTC membership (both state keys)")?;
                tracing::info!(
                    state_key = plain_key.as_ref(),
                    event_id = %resp.event_id,
                    "cleared RTC membership (unprefixed state key)"
                );
                Ok(())
            }
        }
    }

    /// Resolve the LiveKit JWT-service URL for MatrixRTC from the homeserver's
    /// `/.well-known/matrix/client` `org.matrix.msc4143.rtc_foci[0].livekit_service_url`,
    /// defaulting to [`DEFAULT_LIVEKIT_SERVICE_URL`] when the document is absent
    /// or advertises no LiveKit focus. Best-effort: any fetch/parse failure logs
    /// and falls back to the default (so a call still works on this deployment).
    pub async fn rtc_focus_service_url(&self) -> String {
        match self.fetch_rtc_focus_service_url().await {
            Ok(Some(url)) => {
                tracing::info!(url, "resolved MatrixRTC focus from .well-known");
                url
            }
            Ok(None) => {
                tracing::debug!("no msc4143 rtc_foci in .well-known; using default focus");
                DEFAULT_LIVEKIT_SERVICE_URL.to_owned()
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "failed to read .well-known rtc_foci; using default focus");
                DEFAULT_LIVEKIT_SERVICE_URL.to_owned()
            }
        }
    }

    /// Inner fetch for [`rtc_focus_service_url`]: returns `Ok(Some(url))` only
    /// when a LiveKit focus URL is explicitly advertised.
    async fn fetch_rtc_focus_service_url(&self) -> Result<Option<String>> {
        let base = self.client().homeserver().to_string();
        let base = base.trim_end_matches('/');
        let url = format!("{base}/.well-known/matrix/client");
        let resp = reqwest::get(&url)
            .await
            .with_context(|| format!("GET {url} failed"))?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let json: serde_json::Value = resp.json().await.context(".well-known was not JSON")?;
        let foci = match json.get("org.matrix.msc4143.rtc_foci") {
            Some(serde_json::Value::Array(a)) => a,
            _ => return Ok(None),
        };
        for focus in foci {
            if focus.get("type").and_then(|v| v.as_str()) == Some("livekit") {
                if let Some(u) = focus
                    .get("livekit_service_url")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    return Ok(Some(u.to_owned()));
                }
            }
        }
        Ok(None)
    }
}

/// A fresh, collision-resistant call id. We have no RNG in the default feature
/// set, so derive it from the wall clock in nanoseconds — unique enough for a
/// ring (a real MatrixRTC session id would come from the media layer we don't
/// embed).
fn new_call_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("aqua-{nanos}")
}
