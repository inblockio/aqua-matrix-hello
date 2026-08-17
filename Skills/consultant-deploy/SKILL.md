---
name: consultant-deploy
description: Deploy, relabel, and image-roll dedicated single-target Aqua consultant containers via the generic spawn-consultant.sh + registry + roll-consultant-fleet.sh (replaces per-consultant byte-cloned scripts).
---

# Aqua Consultant Deployment

Deploy and maintain **dedicated, single-target Aqua consultants** — one container per peer, each
running `localhost/aqua-matrix-agent:poc` (the `aqua-matrix-claude-p` backend), bound to exactly
ONE peer MXID by the relay firewall (`authorize(sender == target)` in
[`crates/aqua-matrix-relay`](../../crates/aqua-matrix-relay/src/lib.rs)). Each consultant is a
read-only Aqua-protocol assistant grounded in six repos mounted read-only at `/refs`:
`aqua-rs-sdk` (reference implementation), `aqua-spec` (authoritative spec),
`aqua-ecosystem` (trust-layer map: tiers, products, per-repo registry facts),
`aqua-governance-corpus` (governance principles, ICT kernels, deliberation methods),
`aqua-compliance` (regulatory positioning across jurisdictions), and
`inblockio.github.io` (the published inblock.io website: products, positioning, team).
The system prompt in `consultant-config.template.json` tells the agent how to use each.

This skill replaces the old approach of hand-cloning a `recreate-<label>-consultant.sh` per peer.
One generic launcher does it all; a registry + roller image-upgrades the whole fleet.

## Canonical source vs. host copies

The generic tooling is **canonical in this skill directory** and version-controlled here; the host
runs it via symlinks so there is a single source of truth (no drift):

| Canonical (in repo) | Host path (symlink → canonical) | Role |
|---|---|---|
| `Skills/consultant-deploy/spawn-consultant.sh` | `~/spawn-consultant.sh` | generic launcher |
| `Skills/consultant-deploy/roll-consultant-fleet.sh` | `~/roll-consultant-fleet.sh` | fleet image-roller |
| `Skills/consultant-deploy/restore-agent-fleet.sh` | `~/restore-agent-fleet.sh` | boot-time fleet restore (see below) |
| `Skills/consultant-deploy/consultant-config.template.json` | `~/.aqua-matrix-test/consultant-config.template.json` | config template |
| `Skills/consultant-deploy/consultants.registry.example` | *(host state — not symlinked)* | format reference |

**Host state stays on the host** (not in the repo): the live registry
`~/.aqua-matrix-test/consultants.registry`, and every consultant's `<label>-aqua-consultant-config.json`
+ `<label>-aqua-consultant-persist/{store,memory}` under `~/.aqua-matrix-test/`. Persist holds the
self-minted DID (`store/agent.pem`) + memory — it is the identity, preserved across re-runs.

Edit the scripts **here in the repo**; the host symlinks pick the change up immediately.

## Prerequisites

- Image built: `bash ~/aqua-agents/scripts/build-image.sh` (stages the 4 sibling repos + host `claude`, retags `:poc`).
- Refs checkouts on the host: `~/aqua-rs-sdk`, `~/aqua-spec`, `~/aqua-governance-corpus`,
  `~/aqua-ecosystem`, `~/aqua-compliance`, `~/inblockio.github.io` (all under
  `github.com/inblockio/`). The spawner mounts them ro at
  `/refs/<name>` and **refuses to launch if one is missing** (it prints the exact clone command).
- OAuth token at `~/.aqua-matrix-heartbeat/claude-oauth-token` (passed **by reference** — never on a command line).
- `~/.aqua-matrix-notify/notify-tim.sh` (operator DMs) and `target/debug/aqua-activity-watch` (built) for the watcher.

## Add a new consultant

One command. Renders the config from the template, launches with the hardened podman flags, wires
a systemd activity-watcher, and (`--onboard`) DMs the operator a forward-ready onboarding message
carrying the agent's self-minted MXID for the peer to DM:

```bash
bash ~/spawn-consultant.sh \
  --label gawain \
  --target '@did-key-…:matrix.inblock.io' \
  --display 'Aqua Consultant (Gawain)' \
  --name Gawain \
  --onboard
```

**Before spawning, ALWAYS diff the new `--target` against existing configs** — a did:key Tim gives
with a fresh human name may already have a consultant (this is exactly how "Aubert" turned out to be
the existing `zdnaez` peer):

```bash
grep -l 'THE_DID_KEY_LOCALPART' ~/.aqua-matrix-test/*-config.json   # any hit = already deployed
```

Then add the consultant to the live registry so the fleet roller includes it:
```bash
printf 'gawain\t@did-key-…:matrix.inblock.io\tAqua Consultant (Gawain)\n' >> ~/.aqua-matrix-test/consultants.registry
```

## Relabel / re-point an existing consultant

Change the Matrix display name (or rebind the target) while **preserving the DID, memory, and any
hand-customized config** (the render *merges* onto the existing config, overriding only
id/target/display). Uses `--replace` (rm -f + re-run; DID survives via the persist volume):

```bash
bash ~/spawn-consultant.sh --replace \
  --label zdnaez \
  --target '@did-key-…:matrix.inblock.io' \
  --display 'Aqua Consultant (Aubert)'
```

For a display-only tweak with zero container churn, edit `<label>-...-config.json` `.display_name`
and `podman restart <container>` (the daemon re-applies it idempotently on reconnect).

## Image-roll the whole fleet

After rebuilding the image, roll every registry consultant onto it. DIDs + memory preserved (persist
reused); configs used **verbatim** (`--keep-config`, never re-rendered) so custom hello/homeserver
survive. The reserved registry label `generic` covers the **un-labeled operator-bound consultant**
(`aqua-agent-aqua-consultant-1`, config `aqua-consultant-config.json`, persist
`aqua-consultant-persist` — no `<label>-` prefix): the roller translates it to
`spawn-consultant.sh --generic`, so one roll covers the whole consultant fleet. Only
`aqua-agent-tim-channel` stays excluded (different backend; `SEED=0 bash ~/recreate-tim-channel.sh`).

```bash
bash ~/roll-consultant-fleet.sh --dry-run     # preview
bash ~/roll-consultant-fleet.sh --build        # rebuild image, then roll all
```

After a **template prompt change** (a new grounding repo, a new behavioural rule), plain
`--keep-config` would leave existing consultants on the old prompt. Add `--refresh-prompt`
so each kept config adopts the template's current `system_prompt`/`description`/`ref_mounts`
while everything else (hello, homeserver, DID, memory) is preserved:

```bash
bash ~/roll-consultant-fleet.sh --refresh-prompt
```

## Refs grounding and freshness (automatic)

The agent's knowledge is the live host checkouts, bind-mounted read-only; a host-side
`git pull` is visible to running consultants immediately. On **every** launch (spawn,
relabel, and each consultant of a fleet roll) the spawner runs a refs check over the
`REFS_REPOS` list, so a rebuild can never ship stale or missing grounding:

| Repo state | Behaviour |
|---|---|
| missing on host | **FATAL**: refuses to launch, prints the `git clone` command |
| clean + behind upstream | fast-forward pull, logs old/new state |
| dirty + behind | loud warning, mounted as-is (local work never touched) |
| diverged from upstream | loud warning, mounted as-is (resolve manually) |
| fetch fails (offline) / no upstream / not a git checkout | warning, mounted as-is |

`--no-refresh-refs` skips the freshness pass (presence stays fatal). The mount flags,
the presence check, and the freshness pass are all driven by the single `REFS_REPOS`
list in `spawn-consultant.sh`; keep that list in sync with `ref_mounts` in
`consultant-config.template.json` (which the system prompt mirrors).

## Identity & lifecycle flags

| Flag | Effect |
|---|---|
| *(none)* | New container; refuses if one already exists. Fresh DID self-minted on first connect. |
| `--generic` | Select the **un-labeled** operator-bound consultant instead of a `--label` one (container `aqua-agent-aqua-consultant-1`, config/persist without the `<label>-` prefix). Identical behaviour except no activity watcher is wired (the peer IS the operator). Mutually exclusive with `--label`; the registry label `generic` is reserved to map here. |
| `--replace` | `podman rm -f` + re-run, **reusing persist** → DID + memory PRESERVED (the image-roll path). |
| `--keep-config` | Use the existing config verbatim (no re-render); derives id/target/display from it. |
| `--fresh` | Wipe the persist dir first → brand-new identity + empty memory. (Rejected with `--keep-config`.) |
| `--onboard` | After connect, derive the agent MXID from logs and DM the operator a forward-ready onboarding message. |
| `--no-refresh-refs` | Skip the refs freshness pass (fetch/ff-pull). Presence of every refs repo is still enforced. |
| `--refresh-prompt` | Adopt the template's current `system_prompt`/`description`/`ref_mounts` into the config; hello/homeserver customizations, DID, and memory preserved. The sanctioned way to push a prompt update to existing consultants. |

## Invariants the tooling enforces (verified by adversarial audit, 2026-06-08)

- **Security posture is byte-identical** to the proven original `recreate-zdnaez-consultant.sh`
  for the resource/caps/token flags: `--restart on-failure`, `--memory 2048m --cpus 2 --pids-limit 512`,
  `--cap-drop ALL`, `--security-opt no-new-privileges`, `--tmpfs /tmp`, OAuth token passed
  **by reference** (`-e CLAUDE_CODE_OAUTH_TOKEN`, no value).
  Keep it that way — verify after any edit:
  ```bash
  diff <(grep -E '^\s*(--restart|--memory|--cpus|--pids-limit|--cap-drop|--security-opt|--tmpfs|-e )' ~/recreate-zdnaez-consultant.sh) \
       <(grep -E '^\s*(--restart|--memory|--cpus|--pids-limit|--cap-drop|--security-opt|--tmpfs|-e )' ~/spawn-consultant.sh)
  ```
- **Mounts**: config mounted `:ro`, persist store/memory mounted `:U`, every `REFS_REPOS` repo
  mounted `:ro`. Since 2026-06-12 the refs mounts are list-driven and the legacy two-mount
  baseline was deliberately extended with `aqua-governance-corpus` + `aqua-ecosystem`, so the
  `-v` lines no longer byte-match the legacy script (the flag diff above intentionally excludes
  them). Verify nothing mounts writable:
  ```bash
  grep -n 'REF_MOUNT_ARGS+' ~/spawn-consultant.sh        # the one mount template; must end :ro
  podman inspect aqua-agent-<label>-aqua-consultant-1 \
    --format '{{range .Mounts}}{{.Destination}} rw={{.RW}}{{"\n"}}{{end}}'   # every /refs/* rw=false
  ```
- **Single-target binding** — the relay matches one exact target; never widen a consultant to >1 peer.
- **Guards**: placeholder/non-MXID target rejected; `--display` rejects quote/newline (systemd-unit
  injection); registry parser skips indented comments and rejects non-slug labels; `--fresh` asserts
  the persist-path prefix before any `rm -rf`.

## Boot-time restore (reboot survival)

Podman restart policies don't survive a WSL/VM reboot, and the fleet's `--restart on-failure`
never fires on the clean SIGTERM exit a shutdown produces — without help, **every** container
(consultants AND the Tim-bound pair) sits in `exited` after a reboot until someone starts it
(this silenced the whole fleet for 9h on 2026-06-10). Two pieces close that hole:

- **`aqua-agent-fleet-restore.service`** (systemd user oneshot, enabled, runs at boot; unit
  canonical at [`systemd/aqua-agent-fleet-restore.service`](../../systemd/aqua-agent-fleet-restore.service)) runs
  `~/restore-agent-fleet.sh`, which `podman start`s every exited `aqua-agent-*` container.
  Identity/memory live in the persist volumes, so agents come back `store_wiped=false`.
  Caveat: it restarts intentionally-stopped containers too — `podman rm` (or rename away from
  the `aqua-agent-` prefix) anything that must stay down across reboots.
- **`crashloop-watch.sh`** (host-canonical at `~/.aqua-matrix-notify/`) now re-alerts every
  hour while a container stays down (`--realert 3600`) and only counts an alert as sent when
  the DM actually delivered (failed sends retry every 15s poll). The watcher unit is ordered
  `After=aqua-agent-fleet-restore.service` so a normal reboot stays quiet.

Recovery matrix: [`docs/RECOVERY.md`](../../docs/RECOVERY.md).

## Verify a deployment

```bash
podman ps --filter name=aqua-agent-<label>            # Up, restarts 0
podman logs aqua-agent-<label>-aqua-consultant-1 | grep -E 'agent DID|connected|display name set|daemon starting'
systemctl --user is-active aqua-activity-watch-<label>.service   # n/a for --generic (no watcher by design)
podman inspect aqua-agent-<label>-aqua-consultant-1 \
  --format '{{range .Mounts}}{{.Destination}} {{end}}'   # expect all four /refs/* + config + store + memory
```

For the generic consultant the container name is plain `aqua-agent-aqua-consultant-1` (no label).

Healthy = `daemon starting (target: <the one peer>)`, `connected store_wiped=false` (for `--replace`),
and `display name set to "<your display>"`. Then the peer DMs the agent's `@did-key-…:matrix.inblock.io`
MXID (shown in the onboarding message / derivable from the `agent DID:` log line, lowercased).

## Related

- Memory: `consultant-fleet-recreate` (procedure + legacy per-script notes), `gawain-aqua-consultant`,
  `zdnaez-aqua-consultant` (= "Aubert"), `notify-tim-channel`, `relay-mxid-auth-case`.
- Skills: [`claude-channel`](../claude-channel/skill.md) (the backend daemon), [`heartbeat`](../heartbeat/skill.md).
