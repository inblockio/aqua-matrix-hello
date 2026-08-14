//! Rich-media capabilities for [`AgentClient`]: send files, images, audio,
//! video and (MSC3245) voice messages into an E2E-encrypted DM, and download
//! the bytes of an inbound attachment.
//!
//! ## Design
//!
//! Everything funnels through [`matrix_sdk::room::Room::send_attachment`], which
//! — for an encrypted room — uploads the file *encrypted* and attaches the
//! decryption keys to the event automatically (see `room/mod.rs` in matrix-sdk
//! 0.17, the `latest_encryption_state().is_encrypted()` branch). So no caller
//! ever touches the content repository or crypto directly: hand us a path, we
//! pick the msgtype from the MIME top-level type (`image/*` → `m.image`,
//! `audio/*` → `m.audio`, `video/*` → `m.video`, else `m.file`) and send.
//!
//! ## What stays out of the connector
//!
//! Audio/video *decoding* lives in the backend, not here: a voice message needs
//! a duration and a waveform, but decoding an opus blob to compute them would
//! drag a media stack into this lightweight crate. So [`AgentClient::send_voice_message`]
//! takes the `duration_ms` from the caller (who encoded the audio and already
//! knows it) and synthesises a plausible waveform when none is supplied. Image
//! dimensions are the one exception — [`imagesize`] reads them straight from the
//! header bytes with no full decode, so we fill them in for free.
//!
//! ## Receiving
//!
//! Inbound media is surfaced to a handler by the relay as an `InboundMedia`
//! carrying a [`MediaHandle`]. The handler calls [`AgentClient::download_media`]
//! (or [`AgentClient::download_media_to_temp`]) to pull the — automatically
//! decrypted — bytes. The handle keeps the matrix-sdk `MediaSource` private so a
//! handler never names a Matrix type.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use matrix_sdk::attachment::{
    AttachmentConfig, AttachmentInfo, BaseAudioInfo, BaseFileInfo, BaseImageInfo, BaseVideoInfo,
};
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::events::room::message::{MessageType, TextMessageEventContent};
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use matrix_sdk::ruma::{RoomId, UInt, UserId};
use mime::Mime;

use crate::AgentClient;

/// The five kinds of attachment the connector understands, derived from the
/// inbound Matrix `msgtype`. `Voice` is an `m.audio` carrying the MSC3245 voice
/// marker; plain `m.audio` is `Audio`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Audio,
    Voice,
    Video,
    File,
}

impl MediaKind {
    /// Stable lowercase label for logs / JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            MediaKind::Image => "image",
            MediaKind::Audio => "audio",
            MediaKind::Voice => "voice",
            MediaKind::Video => "video",
            MediaKind::File => "file",
        }
    }
}

/// An opaque, connector-owned handle to an inbound attachment's bytes.
///
/// It wraps the matrix-sdk `MediaSource` (kept private, so a handler crate never
/// names a Matrix type) plus the metadata a backend needs to name/save the file.
/// Pass it back to [`AgentClient::download_media`] to fetch the decrypted bytes.
#[derive(Clone, Debug)]
pub struct MediaHandle {
    source: MediaSource,
    /// Best filename for the attachment (the event's `filename`/`body`).
    pub filename: String,
    /// Declared content-type, if the sender provided one.
    pub mimetype: Option<String>,
    /// Declared size in bytes, if known.
    pub size: Option<u64>,
}

impl MediaHandle {
    /// Build a handle from a matrix-sdk media source. Called by the relay while
    /// decoding an inbound event; not part of a handler's surface.
    pub fn new(
        source: MediaSource,
        filename: String,
        mimetype: Option<String>,
        size: Option<u64>,
    ) -> Self {
        Self {
            source,
            filename,
            mimetype,
            size,
        }
    }
}

/// `usize` → ruma `UInt` (saturating to `None` on the impossible >2^53 case),
/// for the size/dimension fields of the attachment info blocks.
fn uint(n: usize) -> Option<UInt> {
    UInt::new(n as u64)
}

/// Synthesise a gentle, deterministic waveform (`0.0..=1.0`) for a voice message
/// when the caller hasn't measured one. ~1 bar per 60 ms, clamped to a sane
/// 24..=120 bars, so Element X renders a voice bubble of the right length
/// instead of a generic audio file. Not a real amplitude envelope — just enough
/// shape that the UI looks like speech.
fn synth_waveform(duration_ms: u64) -> Vec<f32> {
    let bars = ((duration_ms / 60).clamp(24, 120)) as usize;
    (0..bars)
        .map(|i| {
            // Two out-of-phase sines → an organic-looking, non-flat envelope.
            let t = i as f32;
            let v = 0.45 + 0.30 * (t * 0.7).sin() + 0.15 * (t * 0.27).cos();
            v.clamp(0.05, 1.0)
        })
        .collect()
}

impl AgentClient {
    /// Find the existing DM room with `target`, or create one, then best-effort
    /// mark it as a direct chat (`m.direct`) — deduping so the list doesn't grow
    /// unboundedly. Shared by [`send_dm`](Self::send_dm) and every media send so
    /// they all land in the *same* room (splitting media into a second room
    /// would break Megolm key sharing with the peer).
    pub(crate) async fn ensure_dm_room(&self, target: &UserId) -> Result<matrix_sdk::Room> {
        let room = match self.find_dm_room(target).await {
            Some(room) => room,
            None => {
                let room = self
                    .client()
                    .create_dm(target)
                    .await
                    .context("create_dm failed")?;
                // A freshly created DM must match the fleet's E2EE posture even
                // when the homeserver does not force encryption for the DM
                // preset: enable it explicitly. Best-effort — a failure leaves
                // an unencrypted-but-functional room rather than no room.
                match room.latest_encryption_state().await {
                    Ok(state) if state.is_encrypted() => {}
                    _ => {
                        if let Err(e) = room.enable_encryption().await {
                            tracing::warn!("failed to enable encryption on fresh DM: {e:#}");
                        }
                    }
                }
                room
            }
        };
        let already_marked = self
            .client()
            .get_dm_room(target)
            .is_some_and(|r| r.room_id() == room.room_id());
        if !already_marked {
            if let Err(e) = self
                .client()
                .account()
                .mark_as_dm(room.room_id(), &[target.to_owned()])
                .await
            {
                tracing::warn!("failed to mark room as DM (m.direct): {e:#}");
            }
        }
        Ok(room)
    }

    /// Low-level send: resolve the DM room and upload `data` as an attachment.
    /// In an encrypted room matrix-sdk uploads it encrypted and attaches the
    /// keys; callers do nothing special. Returns the event id.
    async fn send_attachment_inner(
        &self,
        target: &str,
        filename: &str,
        content_type: &Mime,
        data: Vec<u8>,
        config: AttachmentConfig,
    ) -> Result<String> {
        let target: &UserId = target
            .try_into()
            .map_err(|e| anyhow!("invalid target: {e}"))?;
        let room = self.ensure_dm_room(target).await?;
        let resp = room
            .send_attachment(filename.to_owned(), content_type, data, config)
            .await
            .context("failed to send attachment")?;
        Ok(resp.event_id.to_string())
    }

    /// Send an arbitrary file as `m.file`. MIME is guessed from the extension
    /// (falling back to `application/octet-stream`). `caption` rides as the
    /// message's caption when present.
    pub async fn send_file(
        &self,
        target: &str,
        path: impl AsRef<Path>,
        caption: Option<&str>,
    ) -> Result<String> {
        let path = path.as_ref();
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let filename = file_name_of(path, "file");
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        let info = AttachmentInfo::File(BaseFileInfo { size: uint(data.len()) });
        let config = attach_config(info, caption);
        self.send_attachment_inner(target, &filename, &mime, data, config)
            .await
    }

    /// [`send_file`](Self::send_file) wrapped with a refresh-then-retry on
    /// `M_UNKNOWN_TOKEN`, mirroring [`crate::AgentClient::send_dm_reliable_with_refresh`]
    /// (see that method's doc comment for the full rationale). Unlike the DM
    /// sends, `send_file` carries NO internal retry at all, so before this
    /// wrapper a rejected attachment (e.g. a markdown-file delivery from
    /// `MdBridge`) aborted straight to its plain-text fallback on the very
    /// first error, with zero retry or reauth attempt. On `M_UNKNOWN_TOKEN`
    /// specifically, reauth once and resend the same file once more.
    pub async fn send_file_with_refresh(
        &mut self,
        target: &str,
        path: impl AsRef<Path>,
        caption: Option<&str>,
    ) -> Result<String> {
        let path = path.as_ref();
        match self.send_file(target, path, caption).await {
            Ok(id) => Ok(id),
            Err(e) if crate::is_unknown_token(&e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "file send rejected with M_UNKNOWN_TOKEN; refreshing token and retrying once"
                );
                self.reauth_token_only()
                    .await
                    .context("token refresh after M_UNKNOWN_TOKEN failed")?;
                self.send_file(target, path, caption)
                    .await
                    .context("file send still failed after token refresh")
            }
            Err(e) => Err(e),
        }
    }

    /// Send an image as `m.image`. Width/height are read from the header bytes
    /// (no full decode) so clients can lay the bubble out before downloading.
    /// Forces an `image/*` content-type so the homeserver records it as an image.
    pub async fn send_image(
        &self,
        target: &str,
        path: impl AsRef<Path>,
        caption: Option<&str>,
    ) -> Result<String> {
        let path = path.as_ref();
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let filename = file_name_of(path, "image");
        // The SDK picks the msgtype from the MIME top-level type, so an image
        // MUST carry an `image/*` type or it would be sent as a plain file.
        let mime = mime_guess::from_path(path)
            .first()
            .filter(|m| m.type_() == mime::IMAGE)
            .unwrap_or(mime::IMAGE_PNG);
        let (width, height) = match imagesize::blob_size(&data) {
            Ok(dim) => (uint(dim.width), uint(dim.height)),
            Err(_) => (None, None),
        };
        let info = AttachmentInfo::Image(BaseImageInfo {
            width,
            height,
            size: uint(data.len()),
            blurhash: None,
            is_animated: None,
        });
        let config = attach_config(info, caption);
        self.send_attachment_inner(target, &filename, &mime, data, config)
            .await
    }

    /// Send a plain audio clip as `m.audio` (no voice marker). For a voice note
    /// that Element renders as a waveform bubble use [`send_voice_message`](Self::send_voice_message).
    pub async fn send_audio(&self, target: &str, path: impl AsRef<Path>) -> Result<String> {
        let path = path.as_ref();
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let filename = file_name_of(path, "audio");
        let mime = audio_mime(path);
        let info = AttachmentInfo::Audio(BaseAudioInfo {
            duration: None,
            size: uint(data.len()),
            waveform: None,
        });
        let config = AttachmentConfig::new().info(info);
        self.send_attachment_inner(target, &filename, &mime, data, config)
            .await
    }

    /// Send a video as `m.video`.
    pub async fn send_video(
        &self,
        target: &str,
        path: impl AsRef<Path>,
        caption: Option<&str>,
    ) -> Result<String> {
        let path = path.as_ref();
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let filename = file_name_of(path, "video");
        let mime = mime_guess::from_path(path)
            .first()
            .filter(|m| m.type_() == mime::VIDEO)
            .unwrap_or_else(|| "video/mp4".parse().expect("static mime"));
        let info = AttachmentInfo::Video(BaseVideoInfo {
            duration: None,
            width: None,
            height: None,
            size: uint(data.len()),
            blurhash: None,
        });
        let config = attach_config(info, caption);
        self.send_attachment_inner(target, &filename, &mime, data, config)
            .await
    }

    /// Send a **voice message** (`m.audio` + MSC3245 markers) so Element X shows
    /// a playable waveform bubble, not a file. The caller supplies `duration_ms`
    /// (known from encoding); `waveform` (amplitudes in `0.0..=1.0`) is optional
    /// — a plausible one is synthesised when omitted. The content-type is forced
    /// to `audio/*` (defaulting to `audio/ogg`, the opus container Element uses).
    pub async fn send_voice_message(
        &self,
        target: &str,
        path: impl AsRef<Path>,
        duration_ms: u64,
        waveform: Option<Vec<f32>>,
    ) -> Result<String> {
        let path = path.as_ref();
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let filename = file_name_of(path, "voice.ogg");
        let mime = audio_mime(path);
        let waveform = waveform.unwrap_or_else(|| synth_waveform(duration_ms));
        let info = AttachmentInfo::Voice(BaseAudioInfo {
            duration: Some(Duration::from_millis(duration_ms)),
            size: uint(data.len()),
            waveform: Some(waveform),
        });
        let config = AttachmentConfig::new().info(info);
        self.send_attachment_inner(target, &filename, &mime, data, config)
            .await
    }

    /// Download (and, if encrypted, transparently decrypt) the bytes of an
    /// inbound attachment described by `handle`. The matrix-sdk media layer
    /// handles `MediaSource::Encrypted` automatically.
    pub async fn download_media(&self, handle: &MediaHandle) -> Result<Vec<u8>> {
        let request = MediaRequestParameters {
            source: handle.source.clone(),
            format: MediaFormat::File,
        };
        let bytes = self
            .client()
            .media()
            .get_media_content(&request, true)
            .await
            .context("failed to download media")?;
        Ok(bytes)
    }

    /// Download an inbound attachment and write it to `dir`, returning the path.
    /// The filename from the handle is sanitised to a basename so a malicious
    /// `../` filename can't escape `dir`.
    pub async fn download_media_to_temp(
        &self,
        handle: &MediaHandle,
        dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let bytes = self.download_media(handle).await?;
        let dir = dir.as_ref();
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("failed to create {}", dir.display()))?;
        let safe = sanitize_filename(&handle.filename);
        let path = dir.join(safe);
        tokio::fs::write(&path, &bytes)
            .await
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(path)
    }

    /// Scan the most recent `limit` timeline events of `room_id` and return every
    /// media attachment found, newest first, as `(kind, handle)` pairs ready to
    /// pass to [`download_media`](Self::download_media). Text/notice/state events
    /// are skipped; undecryptable events are skipped silently. The same field
    /// extraction the relay performs on a live event, applied to history — handy
    /// for a backend that wants to enumerate attachments after a sync.
    pub async fn recent_media(
        &self,
        room_id: &str,
        limit: u16,
    ) -> Result<Vec<(MediaKind, MediaHandle)>> {
        let room_id: &RoomId = room_id
            .try_into()
            .map_err(|e| anyhow!("invalid room_id: {e}"))?;
        let room = self
            .client()
            .get_room(room_id)
            .ok_or_else(|| anyhow!("room {room_id} not found"))?;

        let mut opts = MessagesOptions::backward();
        opts.limit = UInt::from(limit);
        let resp = room
            .messages(opts)
            .await
            .context("failed to fetch messages")?;

        let mut out = Vec::new();
        for event in resp.chunk {
            // Skip undecryptable (UTD) and non-message events.
            if event.kind.is_utd() {
                continue;
            }
            let Ok(deserialized) = event.raw().deserialize() else {
                continue;
            };
            let AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
                msg_event,
            )) = deserialized
            else {
                continue;
            };
            let Some(original) = msg_event.as_original() else {
                continue;
            };
            if let Some(pair) = media_pair(&original.content.msgtype) {
                out.push(pair);
            }
        }
        Ok(out)
    }
}

/// Map a `MessageType` to `(kind, handle)` for the four attachment msgtypes,
/// pulling `source` / `filename` / `mimetype` / `size` exactly as the relay's
/// decoders do. An `m.audio` carrying the MSC3245 voice marker reports
/// [`MediaKind::Voice`]. Returns `None` for non-media msgtypes (text/etc.).
fn media_pair(msgtype: &MessageType) -> Option<(MediaKind, MediaHandle)> {
    match msgtype {
        MessageType::Image(c) => {
            let info = c.info.as_deref();
            let mimetype = info.and_then(|i| i.mimetype.clone());
            let size = info.and_then(|i| i.size).map(u64::from);
            Some((
                MediaKind::Image,
                MediaHandle::new(c.source.clone(), c.filename().to_string(), mimetype, size),
            ))
        }
        MessageType::Audio(c) => {
            let info = c.info.as_deref();
            let mimetype = info.and_then(|i| i.mimetype.clone());
            let size = info.and_then(|i| i.size).map(u64::from);
            let kind = if c.voice.is_some() {
                MediaKind::Voice
            } else {
                MediaKind::Audio
            };
            Some((
                kind,
                MediaHandle::new(c.source.clone(), c.filename().to_string(), mimetype, size),
            ))
        }
        MessageType::Video(c) => {
            let info = c.info.as_deref();
            let mimetype = info.and_then(|i| i.mimetype.clone());
            let size = info.and_then(|i| i.size).map(u64::from);
            Some((
                MediaKind::Video,
                MediaHandle::new(c.source.clone(), c.filename().to_string(), mimetype, size),
            ))
        }
        MessageType::File(c) => {
            let info = c.info.as_deref();
            let mimetype = info.and_then(|i| i.mimetype.clone());
            let size = info.and_then(|i| i.size).map(u64::from);
            Some((
                MediaKind::File,
                MediaHandle::new(c.source.clone(), c.filename().to_string(), mimetype, size),
            ))
        }
        _ => None,
    }
}

/// Build an `AttachmentConfig` carrying `info` and an optional plain-text caption.
fn attach_config(info: AttachmentInfo, caption: Option<&str>) -> AttachmentConfig {
    let config = AttachmentConfig::new().info(info);
    match caption {
        Some(text) => config.caption(Some(TextMessageEventContent::plain(text))),
        None => config,
    }
}

/// The basename of `path` as a `String`, or `fallback` if it has none.
fn file_name_of(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(fallback)
        .to_string()
}

/// Pick an `audio/*` MIME for `path`, defaulting to `audio/ogg` (opus) so the
/// SDK takes its audio branch even when the extension is unknown.
fn audio_mime(path: &Path) -> Mime {
    mime_guess::from_path(path)
        .first()
        .filter(|m| m.type_() == mime::AUDIO)
        .unwrap_or_else(|| "audio/ogg".parse().expect("static mime"))
}

/// Reduce a (possibly hostile) filename to a safe basename: strip any path
/// components, reject empties, and cap the length.
fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_start_matches('.');
    let base = if base.is_empty() { "download" } else { base };
    base.chars().take(128).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waveform_is_normalised_and_sized() {
        for ms in [0u64, 500, 3_000, 60_000, 600_000] {
            let w = synth_waveform(ms);
            assert!(w.len() >= 24 && w.len() <= 120, "len {} for {ms}ms", w.len());
            assert!(
                w.iter().all(|v| (0.0..=1.0).contains(v)),
                "waveform out of range for {ms}ms"
            );
        }
    }

    #[test]
    fn sanitize_strips_path_traversal() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("a/b/c.png"), "c.png");
        assert_eq!(sanitize_filename("c:\\windows\\evil.exe"), "evil.exe");
        assert_eq!(sanitize_filename("   "), "download");
        assert_eq!(sanitize_filename(""), "download");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
    }

    #[test]
    fn media_kind_labels() {
        assert_eq!(MediaKind::Voice.as_str(), "voice");
        assert_eq!(MediaKind::Image.as_str(), "image");
        assert_eq!(MediaKind::File.as_str(), "file");
    }

    #[test]
    fn audio_mime_defaults_to_ogg() {
        assert_eq!(audio_mime(Path::new("note")).essence_str(), "audio/ogg");
        assert_eq!(audio_mime(Path::new("note.txt")).essence_str(), "audio/ogg");
        assert_eq!(audio_mime(Path::new("clip.mp3")).type_(), mime::AUDIO);
    }
}
