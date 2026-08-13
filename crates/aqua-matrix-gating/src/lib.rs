//! aqua-matrix-gating — the connector-side confirmation/gating substrate.
//!
//! This crate is the agent/transport-agnostic core of the chat-confirmations
//! flow, extracted out of the Claude backend so any backend can reuse it. None
//! of it mentions `claude`. It provides three pieces:
//!
//! - [`PendingMap`] — the shared `ask_user` primitive: a pending-reply router
//!   that lets a run pause and ask the authenticated user a question over the
//!   same Matrix channel, resolving on their next DM.
//! - [`destructive`] — a small, table-driven matcher that decides whether a
//!   request is dangerous enough to gate behind a confirmation.
//! - [`AskBridge`] / [`accept_loop`] — the per-run `ask_human` unix-socket
//!   bridge backing the `aqua-matrix-ask-mcp` MCP tool.
//!
//! ## Cross-boundary invariant (connector ↔ agents)
//!
//! [`PendingMap`] alone does **NOT** serialize runs. The "one open question per
//! target" guarantee also needs the backend's per-target `run_lock`, which stays
//! **agents-side**. So the invariant is split across the crate boundary: this
//! connector crate provides the pending-reply router; the agent backend must
//! hold its own per-target run lock to ensure at most one question is open per
//! target at a time.

// matrix-sdk 0.17's deeply-nested async/crypto types overflow rustc's default
// recursion budget when THIS crate's own `tokio::spawn`s need to prove
// `Send` for a future built from `aqua_matrix_agent::AgentClient` methods
// (`md_bridge`'s accept-loop task, spawned from `MdBridge::setup`, is now one
// of those since the reauth-on-401 fix added `reauth_token_only` calls behind
// `send_dm_chunked_with_refresh`/`send_file_with_refresh`). Same fix, same
// rationale, as the `#![recursion_limit = "256"]` already set in
// `aqua-matrix-agent/src/lib.rs` — the limit is per-crate, so raising it there
// does not cover the check rustc performs here.
#![recursion_limit = "256"]

pub mod destructive;
mod ask_bridge;
mod md_bridge;
mod pending;

pub use ask_bridge::{accept_loop, AskBridge};
pub use md_bridge::MdBridge;
pub use pending::PendingMap;

// Re-export the shared markdown-filename helpers so the backend imports them
// from one place (gating) alongside [`MdBridge`]. The bridge names the
// attachment from the model-supplied filename; the backend backstop names it
// from the document's H1; both use the SAME `slugify`, so they cannot drift.
pub use aqua_matrix_md_mcp::{safe_md_filename, slugify};

/// The MCP server key in the generated `ask_human` `--mcp-config`. The
/// fully-qualified tool name `claude` sees is therefore `mcp__ask__ask_human`
/// (see [`ASK_HUMAN_TOOL`]).
///
/// SINGLE SOURCE OF TRUTH: this used to be `ask_bridge::SERVER_KEY` and a
/// separate `ASK_HUMAN_TOOL` const in the backend's `main.rs`. They could drift;
/// now both live here and a unit test asserts they stay consistent.
pub const ASK_SERVER_KEY: &str = "ask";

/// The fully-qualified `ask_human` MCP tool name the backend merges into
/// `--allowedTools` when the ask bridge is up. Derived from [`ASK_SERVER_KEY`]
/// so the two cannot drift (the `derived_tool_name_matches_server_key` test
/// enforces `ASK_HUMAN_TOOL == "mcp__{ASK_SERVER_KEY}__ask_human"`).
pub const ASK_HUMAN_TOOL: &str = concat!("mcp__", "ask", "__ask_human");

/// System-prompt nudge appended to a run that carries the bridge: tells the
/// model the `ask_human` tool exists and *when* to reach for it. Advisory — the
/// model must choose to call it.
pub const ASK_SYSTEM_PROMPT: &str = "You have an `ask_human` tool (mcp__ask__ask_human) that puts a \
question to the authenticated human operator over the chat channel and blocks until they answer. \
Before any destructive or irreversible action (deleting files, `rm`/`rm -rf`, `git push --force`, \
`git reset --hard`, dropping data, or anything you cannot undo), you MUST call `ask_human` with the \
exact command and its blast radius, and proceed only if the answer authorises it. If it returns an \
error or a denial, do NOT perform the action — stop and report it.";

/// The MCP server key in the generated `send_markdown_file` `--mcp-config`. The
/// fully-qualified tool name `claude` sees is therefore
/// `mcp__md__send_markdown_file` (see [`MD_FILE_TOOL`]).
pub const MD_SERVER_KEY: &str = "md";

/// The fully-qualified `send_markdown_file` MCP tool name the backend merges
/// into `--allowedTools` when the md bridge is up. Derived from [`MD_SERVER_KEY`]
/// so the two cannot drift (the `md_tool_name_matches_server_key` test enforces
/// it).
pub const MD_FILE_TOOL: &str = concat!("mcp__", "md", "__send_markdown_file");

/// The two-pathway markdown protocol, injected via `--append-system-prompt` on
/// every conversational run. It is the SINGLE source of markdown-handling
/// instruction for the agent: pathway A delivers a file via the tool, pathway B
/// replies with an inline fenced code block, and the agent must never report a
/// container path as a deliverable. Kept consistent with the tool results so a
/// `delivered false` never causes a double delivery. No em dashes (house style).
pub const MD_SYSTEM_PROMPT: &str = "You can deliver markdown two ways, and you must pick the right one.\n\n\
PATHWAY A, markdown FILE. If the user asks for the answer as a file (for example \"give me the markdown file\", \"the markdown FILE\", \"send it as a file\", \"as a .md\", \"export this as a markdown file\", \"send me a markdown file\"), call the tool mcp__md__send_markdown_file with a short descriptive filename and the full markdown document as the markdown argument. Do not write, create, or save any file yourself with any other tool for this, and never tell the user a local path or a container path. After the tool returns delivered true, confirm briefly, for example \"Sent it to you as a markdown file.\" If the tool says it could not attach the file but the content was sent another way, do not paste it again; just briefly say it could not be attached as a file. Only if the tool explicitly says nothing was sent should you paste the full document inline.\n\n\
PATHWAY B, markdown OUTPUT. If the user asks for the answer in markdown inline (for example \"in markdown\", \"as markdown\", \"format that as markdown\", \"show the markdown\", without the word file), reply with a single fenced markdown code block: three backticks, then the word markdown, then a newline, the document, and three backticks. Do not attach a file.\n\n\
Disambiguation. The words file, markdown file, .md, attachment, download, or \"send it as a file\" mean PATHWAY A, the tool. The phrases \"in markdown\" or \"as markdown\" without the word file mean PATHWAY B, the inline code block.\n\n\
MUST NOT. Never write the deliverable into your own memory or any container path and then report that path to the user as the deliverable. The user cannot open container paths. Use the tool for files, or an inline code block for output. You may still write to your own memory files for your own continuity, but a memory path is never a deliverable you give the user.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_tool_name_matches_server_key() {
        // The single-source-of-truth guarantee: `ASK_HUMAN_TOOL` must always be
        // `mcp__<ASK_SERVER_KEY>__ask_human`. If `ASK_SERVER_KEY` ever changes,
        // this fails until `ASK_HUMAN_TOOL`'s `concat!` is updated to match.
        assert_eq!(ASK_HUMAN_TOOL, format!("mcp__{ASK_SERVER_KEY}__ask_human"));
    }

    #[test]
    fn md_tool_name_matches_server_key() {
        // Same invariant for the markdown tool: `MD_FILE_TOOL` must always be
        // `mcp__<MD_SERVER_KEY>__send_markdown_file`.
        assert_eq!(MD_FILE_TOOL, format!("mcp__{MD_SERVER_KEY}__send_markdown_file"));
    }

    #[test]
    fn md_system_prompt_has_no_em_or_en_dashes() {
        // House style: the agent-facing protocol must carry no em/en dashes.
        assert!(!MD_SYSTEM_PROMPT.contains('\u{2014}'), "em dash present");
        assert!(!MD_SYSTEM_PROMPT.contains('\u{2013}'), "en dash present");
    }
}
