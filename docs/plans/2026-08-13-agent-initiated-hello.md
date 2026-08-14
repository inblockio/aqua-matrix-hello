# Plan: Agent-initiated DM hello for consultant deployments

Date: 2026-08-12. Branch: `feat/agent-initiated-hello` (worktrees under `~/wt/aih/`, both repos dirty from a concurrent session, so no work in the live checkouts).

## Goal (one sentence)

A newly spawned consultant creates the DM room, invites its binding peer, and delivers its greeting proactively, so the peer's first experience is receiving the consultant's invite and hello instead of having to DM a raw MXID first.

## Why this shape (CONTEXT summary)

- The defer lives in `aqua-matrix-agent/crates/aqua-matrix-relay/src/lib.rs:573-594`: hello is only sent into an EXISTING DM room; otherwise "no DM room yet; deferring hello".
- The comment explains the guard: `create_dm` against a *programmatic* peer that also creates a room splits the two sides into separate rooms and breaks Megolm. Consultant peers are humans who have not DM'd yet (that is the problem being solved), so the hazard window is negligible there. The guard must therefore stay the DEFAULT and the new behavior must be opt-in.
- `AgentClient::send_dm` already resolves-or-creates the room via `ensure_dm_room` (`media.rs:138`: `find_dm_room` else `create_dm`, then dedup-aware `mark_as_dm`). No new client capability is needed for room creation.
- claude-p persists a greeted-marker committed only in `hello_delivered()` (confirmed send), so an undelivered hello retries on the next process start. Delphine (zdnaejx, spawned today, hello still deferred) will greet on her first post-upgrade start.
- `AgentType` is `deny_unknown_fields`: a config field the binary does not know crash-loops the container (the 2026-06-15 avatar_path landmine). Sequencing invariant: binary/image first, configs second. Verified: `--refresh-prompt` adopts only `system_prompt/description/ref_mounts`, so a new template key does NOT leak into kept configs.
- `spawn-consultant.sh` honors `--image` / `CONSULTANT_IMAGE`, and per-instance configs carry an `image` key, so a test image tag can run one container while the fleet stays on `:poc`.
- `build-image.sh` derives `SIBLINGS_ROOT` from its repo location, so a staged worktree root at `~/wt/aih/` (worktrees + symlinks to `siwx-oidc`, `aqua-auth`, `aqua-rs-sdk`) builds hermetically from my branch, without the concurrent session's uncommitted changes.
- Prior art for decryptability: the aqua-e2e harness (13/13 green vs prod) has its fresh identities message each other into freshly created rooms; peers join via invite and verify message CONTENT, which is evidence that Megolm keys are shared with invited members in this stack. Still verified live here (H4).

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | relay first_cycle calls `send_dm` when no DM room exists and the handler opts in | room created, peer invited, `m.direct` marked, hello event persisted | `ensure_dm_room` semantics hold | test-consultant log shows initiate + hello event id; peer sees invite |
| H2 | `initiate_dm: Option<bool>` rides AgentType -> claude-p -> new relay trait method (default false) | flag reaches relay; absent field = exactly old behavior | serde roundtrip under deny_unknown_fields | `cargo test` parse tests with and without the field |
| H3 | new binary ships before any config carries the field | no crash-loop anywhere | roll ordering respected; --refresh-prompt does not leak the key (verified in recon) | old-style config parses on new image (container log passes config-load); test config with field runs RC=0 |
| H4 | hello is sent while the peer is invited-not-yet-joined | peer can decrypt the hello after joining (no UTD) | matrix-sdk shares room keys with invited members (e2e-harness prior art) | scratch peer joins and `--read` shows hello plaintext |
| H5 | the agent-created DM room carries `m.room.encryption` | E2EE posture preserved for agent-initiated rooms | server preset default, else explicit `enable_encryption()` on the create branch | peer-session state probe shows m.room.encryption present |
| H6 | peer replies in the agent-created room | consultant answers in the SAME room; `m.direct` stays single-entry | `find_dm_room` deterministic post-liveness-fix | reply round-trip observed; m.direct probe shows 1 entry |
| H7 | `consultant-config.template.json` gains `"initiate_dm": true` | NEW spawns initiate by default; existing configs untouched | template render only affects fresh renders | rendered test config has the key; live fleet configs diff-clean |
| H8 | Delphine rolled onto new image + flag added to her config | her pending (never-delivered) hello fires proactively to her real peer | greeted marker absent (confirmed today) | her log shows initiate + hello delivered + marker file created |

## Tasks

### Task 1: Worktree setup + image-provenance check
**Hypotheses:** (setup)
- `podman image inspect localhost/aqua-matrix-agent:poc` (created date, id) and compare against git history of both repos to pick the branch base that does not regress the running fleet. Recommendation: base = the commit the current `:poc` was built from if determinable, else `origin/main`; surface if they diverge.
- `git worktree add ~/wt/aih/aqua-matrix-agent -b feat/agent-initiated-hello <base>`; same for `~/wt/aih/aqua-agents`; symlink `siwx-oidc`, `aqua-auth`, `aqua-rs-sdk` into `~/wt/aih/`.
- Confirm my touched files (`relay/src/lib.rs`, `agent/src/media.rs`, `template/src/lib.rs`, `claude-p/src/main.rs`, `Skills/consultant-deploy/*`) do not overlap the concurrent session's dirty files (`agent/src/lib.rs`, `agent/src/recovery.rs`, `aqua-call-agent/*`).

### Task 2: Connector change (relay + media)
**Hypotheses:** H1, H5
- `MessageHandler` gains `fn initiates_dm(&self) -> bool { false }` (documented: only for human peers that never DM first; default keeps the programmatic-peer duplicate-room guard).
- first_cycle `None` branch: if `initiates_dm()`, log "initiating DM (creating room + inviting peer)", `send_dm(&target, &hello)`, `hello_delivered()` on success.
- `ensure_dm_room`: on the `create_dm` branch only, ensure encryption (check state; `enable_encryption()` if absent; warn-not-fatal).
- Gates: `cargo build`, `cargo test`, `scripts/check-dep-direction.sh`.

### Task 3: Agents change (template + claude-p)
**Hypotheses:** H2
- `AgentType`: add `pub initiate_dm: Option<bool>` with doc comment (near `hello`).
- claude-p handler: override `initiates_dm()` from config (`unwrap_or(false)`).
- Parse tests: config with the field, without the field (back-compat), plus existing roundtrip suite. `cargo build && cargo test`.

### Task 4: Deployment glue
**Hypotheses:** H7
- `Skills/consultant-deploy/consultant-config.template.json`: add `"initiate_dm": true`.
- `spawn-consultant.sh --onboard` text: peer now receives her invite directly; forward message becomes "accept her invite" instead of "DM her MXID".
- `Skills/consultant-deploy/skill.md`: document the flag + the image-before-config sequencing rule.

### Task 5: Image build (side tag, no fleet impact)
**Hypotheses:** H3
- Capture current `:poc` image id. Build via `~/wt/aih/aqua-agents/scripts/build-image.sh` (stages the worktree root). It retags `:poc`, so immediately: `podman tag <new> aqua-matrix-agent:aih-test` and restore old id to `:poc`. Fleet untouched.

### Task 6: Live e2e verification (scratch identities, prod homeserver, no fleet involvement)
**Hypotheses:** H1, H3, H4, H5, H6
- Scratch peer identity (fresh pem + store under `~/.aqua-matrix-test/aih-test-peer/`, deleted after); get MXID via `--print-did`.
- Spawn test consultant `--label aih-test --image ...:aih-test` targeting the scratch peer. NOT added to the registry, no `--onboard`. First start renders an old-style config (template in the live checkout has no flag yet): config parses on new binary = H3 evidence, hello defers (flag absent = old behavior, H2 evidence). Then stop, add `"initiate_dm": true` to its config, start again: initiation fires.
- Verify: initiate log + hello event (H1); peer joins + reads hello plaintext (H4); room-state probe shows encryption (H5); peer replies, consultant answers in the same room, m.direct single entry (H6).
- Cleanup: container, persist, config, watcher unit, peer store, leave+forget rooms.

### Task 7: Deploy (Tim-authorized by confirming this plan)
**Hypotheses:** H8
- Promote image: `podman tag ...:aih-test ...:poc`.
- Add `"initiate_dm": true` to `zdnaejx-aqua-consultant-config.json`; `spawn-consultant.sh --replace --keep-config --no-refresh-refs --label zdnaejx`.
- Verify Delphine initiates: room created, hello delivered to her real peer, marker committed, RC=0, no 401 (if the stale-token 401 gotcha fires, restart again within the token window).
- Rest of fleet: NOT rolled (their DM rooms exist; flag is a no-op for them). They pick everything up on the next natural roll.
- Template default (`initiate_dm: true` for future spawns) goes live when the branch lands in the repo checkout the host symlinks point at; presented as a merge decision at audit (the live checkout is another session's branch, I will not touch it).

### Task 8: Audit + docs + memory
- Layer 1 hypothesis trace + Layer 2 acceptance criteria with actual command output.
- Commit + push `feat/agent-initiated-hello` (SSH; verify via `git ls-remote`), update memories (`consultant-fleet-recreate`, `zdnaejx-aqua-consultant`, new feature memory), copy this plan into `docs/plans/`.

## Acceptance Criteria

| # | Criterion | Hypotheses |
|---|-----------|------------|
| AC1 | Fresh consultant with flag creates room + invites peer + sends hello proactively | H1, H2 |
| AC2 | Peer decrypts the hello (no "unable to decrypt" first impression) | H4 |
| AC3 | Agent-created DM room is E2E-encrypted | H5 |
| AC4 | Reply round-trip stays in one room; m.direct single entry | H6 |
| AC5 | Zero regression: old configs on new binary, flag defaults off everywhere else | H2, H3 |
| AC6 | New spawns default to initiating; onboarding text matches the new flow | H7 |
| AC7 | Delphine proactively greets her real peer | H8 |

## Boundary conditions

- **Invariants:** opt-in flag defaults false (heartbeat/tim-channel/existing fleet unchanged); binary-before-config sequencing; one-way dep rule (relay trait in connector, override in agents, `check-dep-direction.sh` gate); never touch the concurrent session's dirty files or branch; test consultant never enters the registry; no fleet-wide roll; never print tokens.
- **Top risks:** (1) hello UTD for invited peer despite prior art: fallback design ready (hold hello pending until peer membership = join), would run as a remediation loop. (2) crash-loop via mis-sequencing: contained by explicit ordering + verified --refresh-prompt behavior. (3) `:poc` retag side effects during build: tag-dance restores the old id immediately.
- **Out of scope:** rolling the other 15 consultants, other backends adopting the flag, multi-room ambiguity beyond current behavior, deployment-glue migration.
