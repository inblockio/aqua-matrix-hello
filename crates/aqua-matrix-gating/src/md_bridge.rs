//! Daemon side of the `send_markdown_file` MCP tool: the bridge that turns a
//! model tool call into a real Matrix `.md` attachment.
//!
//! Structurally a sibling of [`crate::AskBridge`]: the MCP server
//! (`aqua-matrix-md-mcp`) owns **no** Matrix session; this daemon does. For each
//! conversational `claude` run that may deliver a file, the daemon:
//!   1. binds a **per-run unix domain socket** and writes a one-server
//!      `--mcp-config` JSON pointing `claude` at the `aqua-matrix-md-mcp` binary
//!      with `MD_MCP_SOCK` set to that socket;
//!   2. runs an accept loop: each `send_markdown_file` call opens the socket and
//!      sends one [`MdRequest`] line; the loop writes the Markdown to a temp
//!      `.md`, attaches it with [`AgentClient::send_file_with_refresh`], and
//!      writes back one [`MdReply`] line.
//!
//! The DIFFERENCE from `AskBridge`: where the ask bridge routes a question
//! through `PendingMap::ask` (ask a human), this bridge performs the actual file
//! delivery. It also exposes a [`MdBridge::fired`] flag so the backend's
//! post-hoc backstop can tell whether the model already delivered a file and
//! avoid a double attachment.
//!
//! Resilience: on any `send_file` failure (after one reauth-and-retry on
//! `M_UNKNOWN_TOKEN`, via `send_file_with_refresh`) the handler degrades to
//! inline chunked delivery so the content is never lost, and reports which
//! path it took in the reply detail. The filename is model-supplied and
//! therefore UNTRUSTED: it is run through [`safe_md_filename`] before touching
//! the filesystem.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aqua_matrix_md_mcp::ipc::{self, MdReply, MdRequest};
use aqua_matrix_md_mcp::{safe_md_filename, SOCK_ENV};
use aqua_matrix_relay::AgentClient;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::MD_SERVER_KEY;

/// Where the bridge writes the temp `.md` before attaching it. A flat per-host
/// dir under `/tmp` (cleared on reboot), matching the backend's media tmp dir.
const MEDIA_TMP_DIR: &str = "/tmp/aqua-claude-media";

/// A per-run `send_markdown_file` bridge. Holds the bound socket, the generated
/// `--mcp-config` file, the accept-loop task, and a `fired` flag. Dropping it
/// aborts the loop and removes both files (RAII cleanup, no orphaned sockets).
pub struct MdBridge {
    sock_path: PathBuf,
    config_path: PathBuf,
    task: tokio::task::JoinHandle<()>,
    /// Set once the model actually calls the tool during this run. The backend
    /// backstop reads it to avoid attaching a second copy.
    fired: Arc<AtomicBool>,
}

impl MdBridge {
    /// Set up a bridge for one run targeting `target`. Binds the socket, writes
    /// the MCP config, and spawns the accept loop backed by `agent.send_file`.
    ///
    /// Takes `&mut AgentClient` (not `&AgentClient`) for consistency with the
    /// rest of the reauth-on-401 chain: `deliver_file`/`inline_fallback` (called
    /// from the accept loop this spawns) need `&mut AgentClient` to call the
    /// `*_with_refresh` sends, so the caller (claude-p's `stream_claude`) must
    /// already hold the client mutably by the time it gets here.
    pub async fn setup(agent: &mut AgentClient, target: &str) -> anyhow::Result<Self> {
        let id = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir();
        let sock_path = dir.join(format!("aqua-md-{id}.sock"));
        let config_path = dir.join(format!("aqua-md-{id}.json"));

        // A stale socket at this exact path is impossible (fresh uuid), but bind
        // fails if it somehow exists; clear it defensively.
        let _ = tokio::fs::remove_file(&sock_path).await;
        let listener = UnixListener::bind(&sock_path)
            .map_err(|e| anyhow::anyhow!("md-bridge: bind {}: {e}", sock_path.display()))?;

        let mcp_bin = md_mcp_bin_path();
        let config = serde_json::json!({
            "mcpServers": {
                MD_SERVER_KEY: {
                    "command": mcp_bin,
                    "args": [],
                    "env": { SOCK_ENV: sock_path.to_string_lossy() }
                }
            }
        });
        tokio::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)
            .await
            .map_err(|e| anyhow::anyhow!("md-bridge: write config: {e}"))?;

        let fired = Arc::new(AtomicBool::new(false));

        // The loop outlives this fn; give it owned clones. Factor the delivery
        // into a closure so the socket-serving layer (`accept_loop`) is testable
        // with a stub, exactly as the ask bridge does.
        let agent = agent.clone();
        let target = target.to_string();
        let deliver = move |req: MdRequest| {
            let mut agent = agent.clone();
            let target = target.clone();
            async move { deliver_file(&mut agent, &target, &req).await }
        };
        let fired_for_loop = fired.clone();
        let task = tokio::spawn(async move {
            accept_loop(listener, fired_for_loop, deliver).await;
        });

        Ok(Self { sock_path, config_path, task, fired })
    }

    /// Path of the `--mcp-config` file to hand `claude`.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Whether the model called `send_markdown_file` during this run. The
    /// backend backstop attaches the answer as a file ONLY when this is false
    /// (and no inline codebox was produced), preventing a double attachment.
    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for MdBridge {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.sock_path);
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Accept one connection per `send_markdown_file` call and run its delivery
/// through `deliver`. Connections are handled sequentially: the per-target run
/// lock plus `claude` blocking on each tool result mean at most one call is ever
/// in flight, so there is no overlap to parallelise.
pub async fn accept_loop<F, Fut>(listener: UnixListener, fired: Arc<AtomicBool>, deliver: F)
where
    F: Fn(MdRequest) -> Fut,
    Fut: Future<Output = MdReply>,
{
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                if let Err(e) = handle_conn(stream, &fired, &deliver).await {
                    tracing::warn!("md-bridge: connection error: {e:#}");
                }
            }
            Err(e) => {
                tracing::warn!("md-bridge: accept failed: {e}");
                tokio::task::yield_now().await;
            }
        }
    }
}

/// One request/response: read an [`MdRequest`] line, mark the bridge fired,
/// resolve delivery via `deliver`, write the [`MdReply`] line back.
async fn handle_conn<F, Fut>(
    stream: UnixStream,
    fired: &Arc<AtomicBool>,
    deliver: &F,
) -> anyhow::Result<()>
where
    F: Fn(MdRequest) -> Fut,
    Fut: Future<Output = MdReply>,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        anyhow::bail!("md-bridge: peer closed before sending a request");
    }
    let req = ipc::decode_request(&line)?;
    // The model called the tool: record it BEFORE delivery so a slow send can
    // never race the backend's backstop decision (which reads `fired`).
    fired.store(true, Ordering::SeqCst);
    tracing::info!(
        "md-bridge: send_markdown_file filename={:?} ({} bytes)",
        req.filename,
        req.markdown.len()
    );

    let reply = deliver(req).await;

    let mut stream = reader.into_inner();
    stream.write_all(ipc::encode_reply(&reply).as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Perform the actual delivery: write a temp `.md` (named from the sanitized,
/// untrusted model filename), attach it via [`AgentClient::send_file`], and
/// remove the temp file. On any failure, degrade to inline chunked delivery so
/// the content is never lost, and report which path was taken.
async fn deliver_file(agent: &mut AgentClient, target: &str, req: &MdRequest) -> MdReply {
    let filename = safe_md_filename(&req.filename);
    let dir = Path::new(MEDIA_TMP_DIR);
    if let Err(e) = tokio::fs::create_dir_all(dir).await {
        tracing::warn!("md-bridge: can't create {} ({e:#}); delivering inline", dir.display());
        return inline_fallback(agent, target, &req.markdown, format!("temp dir error: {e}")).await;
    }
    let path = dir.join(&filename);
    if let Err(e) = tokio::fs::write(&path, &req.markdown).await {
        tracing::warn!("md-bridge: can't write {} ({e:#}); delivering inline", path.display());
        return inline_fallback(agent, target, &req.markdown, format!("temp write error: {e}")).await;
    }
    let caption = "Here is your answer as a Markdown file. 📎";
    // `_with_refresh`: on M_UNKNOWN_TOKEN (the daemon's `AgentClient` is a
    // per-cycle clone that can outlive the cycle whose token it was minted
    // with — see the reauth-on-401 fix), reauth once and resend once rather
    // than aborting straight to the inline-text fallback below.
    let sent = agent.send_file_with_refresh(target, &path, Some(caption)).await;
    let _ = tokio::fs::remove_file(&path).await; // best-effort cleanup, always
    match sent {
        Ok(ev) => {
            tracing::info!(
                "md-bridge: delivered {filename} to {target} ({} bytes, event {ev})",
                req.markdown.len()
            );
            MdReply::delivered(filename)
        }
        Err(e) => {
            tracing::warn!("md-bridge: send_file to {target} failed ({e:#}); delivering inline");
            inline_fallback(agent, target, &req.markdown, format!("attachment send failed: {e}")).await
        }
    }
}

/// Last-resort delivery so the answer is never lost when the attachment cannot
/// be sent: push the Markdown to the user inline, split across as many messages
/// as needed. Reports `delivered:false` (the FILE was not attached) with a
/// detail saying the content went out inline, so the model does not resend it.
async fn inline_fallback(agent: &mut AgentClient, target: &str, markdown: &str, why: String) -> MdReply {
    match agent.send_dm_chunked_with_refresh(target, markdown).await {
        Ok(_) => MdReply::failed(format!("{why}; sent inline")),
        Err(e) => MdReply::failed(format!("{why}; inline delivery also failed: {e}")),
    }
}

/// Resolve the `aqua-matrix-md-mcp` binary: it is built into the same
/// `target/<profile>/` directory as this daemon (and co-located in
/// `/usr/local/bin` in the image), so look beside `current_exe` first, then fall
/// back to a bare name on `PATH`.
fn md_mcp_bin_path() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("aqua-matrix-md-mcp");
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    "aqua-matrix-md-mcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the socket-serving layer (`accept_loop` + `handle_conn`) end to end
    /// against a stub `deliver`, exactly as the real MCP server would: write one
    /// `MdRequest` line, read one `MdReply` line. The Matrix leg (`send_file`) is
    /// substituted by the stub since that half needs a live room. Returns the
    /// reply plus whether the bridge recorded the call as fired.
    async fn roundtrip<F, Fut>(req: MdRequest, deliver: F) -> (MdReply, bool)
    where
        F: Fn(MdRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = MdReply> + Send,
    {
        let id = uuid::Uuid::new_v4();
        let sock = std::env::temp_dir().join(format!("aqua-md-test-{id}.sock"));
        let listener = UnixListener::bind(&sock).unwrap();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_check = fired.clone();
        let server = tokio::spawn(async move { accept_loop(listener, fired, deliver).await });

        let mut client = UnixStream::connect(&sock).await.unwrap();
        client
            .write_all(ipc::encode_request(&req).as_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        server.abort();
        let _ = std::fs::remove_file(&sock);
        (ipc::decode_reply(&line).unwrap(), fired_check.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn delivered_reply_round_trips_and_sets_fired() {
        let req = MdRequest { filename: "overview".into(), markdown: "# Overview\n\nbody".into() };
        let (reply, fired) = roundtrip(req.clone(), |got| async move {
            assert_eq!(got.filename, "overview");
            assert!(got.markdown.contains("# Overview"));
            MdReply::delivered("overview.md")
        })
        .await;
        assert!(reply.delivered);
        assert_eq!(reply.detail, "overview.md");
        assert!(fired, "receiving a tool call must set the fired flag");
    }

    #[tokio::test]
    async fn failed_reply_round_trips() {
        let req = MdRequest { filename: "x".into(), markdown: "y".into() };
        let (reply, fired) =
            roundtrip(req, |_| async move { MdReply::failed("send_file failed; sent inline") }).await;
        assert!(!reply.delivered);
        assert!(reply.detail.contains("inline"));
        assert!(fired);
    }

    #[test]
    fn mcp_bin_path_falls_back_to_bare_name_when_no_sibling() {
        // No `aqua-matrix-md-mcp` sits beside the test binary, so we deterministically
        // exercise the PATH fallback branch.
        assert_eq!(md_mcp_bin_path(), "aqua-matrix-md-mcp");
    }
}
