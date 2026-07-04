# Integrating hookguard with OpenAI Codex CLI

> **Status:** Codex CLI support is planned and in active development on the `feature/codex` branch. The design is fully resolved — see `docs/Codex-CLI-hook-support-Plan.md` and `docs/adr/0006-codex-ask-downgraded-to-deny.md` through `docs/adr/0008-per-host-default-policy-path.md`. This document describes the intended integration once that work ships.

---

## Overview of differences from Claude Code

Codex CLI uses the same `hookSpecificOutput.permissionDecision` JSON wire format as Claude Code, but there are several important differences:

| Aspect | Claude Code | Codex CLI |
|--------|-------------|-----------|
| `ask` decision | Supported — pauses for user confirmation | **Not supported** — parsed but ignored |
| File edits | Individual `Edit` / `Write` calls per file | Single `apply_patch` call with raw patch text |
| PowerShell on Windows | Separate `tool_name: "PowerShell"` | Reported as `tool_name: "Bash"` |
| Extra stdin fields | `session_id`, `cwd`, `tool_name`, `tool_input` | Also `turn_id`, `tool_use_id`, `permission_mode`, `model`, `transcript_path` |

## The `hookguard codex` subcommand

To invoke hookguard for Codex, pass `codex` as the first argument:

```bash
hookguard codex
```

This tells hookguard which host is calling. The host is **never** inferred from the request body — it is always explicit. The bare `hookguard` command (no argument, or argument `claude`) behaves exactly as before: Claude Code mode.

### Per-host default policy path

| Invocation | Default policy path |
|------------|---------------------|
| `hookguard` / `hookguard claude` | `~/.claude/hookguard.yaml` |
| `hookguard codex` | `~/.codex/hookguard.yaml` |

`HOOKGUARD_POLICY` overrides the default for both hosts.

This lets you maintain a single shared policy or host-specific policies, as needed.

## Ask-to-deny downgrade

Because Codex CLI has no `ask` channel, hookguard automatically downgrades every `ask` decision to `deny` when running as `hookguard codex`. The `permissionDecisionReason` is prefixed to make the downgrade visible:

```
ask downgraded to deny (Codex has no ask channel): <original reason>
```

This downgrade applies to:
- Rule matches that resolve to `ask`
- The `opaque_execution_guard` when configured with `action: ask`
- The `powershell_opaque_execution_guard` when configured with `action: ask`
- The `patch_opaque_execution_guard` when configured with `action: ask`
- The `HOOKGUARD_FAIL_MODE=ask` (missing policy) path

Design rationale: [ADR 0006](adr/0006-codex-ask-downgraded-to-deny.md)

## Registering the hook in Codex CLI

Add to `~/.codex/config.toml`:

```toml
[[hooks]]
  event = "exec"
  command = "hookguard codex"

[[hooks]]
  event = "patch"
  command = "hookguard codex"
```

The `exec` event covers all shell execution (Bash on all platforms, including PowerShell commands reported as Bash on Windows). The `patch` event covers `apply_patch` calls.

To use a custom policy file:

```toml
[[hooks]]
  event = "exec"
  command = "HOOKGUARD_POLICY=/path/to/hookguard.yaml hookguard codex"

[[hooks]]
  event = "patch"
  command = "HOOKGUARD_POLICY=/path/to/hookguard.yaml hookguard codex"
```

## `apply_patch` handling

Codex CLI bundles all file edits for a turn into a single `apply_patch` tool call whose `tool_input.command` contains raw patch text:

```
*** Begin Patch
*** Add File: src/config.go
+package main
+
+var debug = false
*** Update File: src/main.go
@@
-fmt.Println("hello")
+fmt.Println("hello world")
*** Delete File: src/unused.go
*** End Patch
```

hookguard decomposes each `apply_patch` call into **Patch-Segments** — one per file operation — and evaluates each independently against your existing `tools`/`path` rules, exactly as if they were individual `Edit`/`Write` calls. The operation types map as follows:

| Patch operation | Evaluated as | Why |
|-----------------|-------------|-----|
| `*** Add File:` | `Write` | Creating a new file |
| `*** Update File:` | `Edit` | Modifying an existing file |
| `*** Delete File:` | `Edit` | Removing an existing file (treated as Edit for path-rule purposes) |
| `*** Move to:` (source) | `Edit` | Reading from the source path |
| `*** Move to:` (destination) | `Write` | Writing to the destination path |

This means your existing `path`-based rules work for `apply_patch` without any changes. For example:

```yaml
# This rule already blocks apply_patch → Add File: .env
- tools: ["Write"]
  path: "**/.env*"
  action: deny
  reason: "writing .env files may leak secrets"
```

### `patch_opaque_execution_guard`

When an `apply_patch` payload cannot be parsed into Patch-Segments (malformed envelope, unrecognized header format, empty paths), the `patch_opaque_execution_guard` fires:

```yaml
patch_opaque_execution_guard:
  action: ask   # downgraded to deny under Codex
```

Add this block to your `hookguard.yaml` alongside the two existing guards:

```yaml
opaque_execution_guard:
  action: ask

powershell_opaque_execution_guard:
  action: ask

patch_opaque_execution_guard:
  action: ask
```

## PowerShell on Windows under Codex

Codex CLI reports all shell execution as `tool_name: "Bash"`, even on Windows where PowerShell is the actual shell. hookguard detects this combination (`host == codex` + `GOOS == windows` + `tool_name == "Bash"`) and routes the command through the PowerShell parser automatically — so your `cmdlet:` rules apply without any changes to your policy file.

On Linux/macOS under Codex, `tool_name: "Bash"` goes through the Bash parser as expected.

## Extra CEL variables (Codex-only)

When hookguard is invoked as `hookguard codex`, five additional fields from the Codex payload are available in `when:` expressions. They are always empty strings under Claude Code.

| Variable | CEL type | Codex field | Description |
|----------|----------|------------|-------------|
| `turn_id` | `string` | `turn_id` | Identifier for the agent turn |
| `tool_use_id` | `string` | `tool_use_id` | Identifier for the specific tool use |
| `permission_mode` | `string` | `permission_mode` | e.g. `"auto"` or `"manual"` |
| `model` | `string` | `model` | Model name, e.g. `"codex-1"` |
| `transcript_path` | `string` | `transcript_path` | Path to the session transcript file, if provided |

Example use — deny all shell execution when the agent is running in fully automatic mode:

```yaml
- tools: ["Bash"]
  when: 'permission_mode == "auto"'
  action: deny
  reason: "shell execution is not permitted in auto permission mode"
```

## Audit log

The audit log gains a `host` field to distinguish Codex and Claude Code calls:

```jsonl
{"ts":"2026-07-01T10:00:00Z","host":"claude","session_id":"abc","tool_name":"Bash","cmd":"git push --force","action":"deny","reason":"..."}
{"ts":"2026-07-01T10:00:05Z","host":"codex","session_id":"def","tool_name":"Bash","cmd":"rm -rf dist/","action":"ask","reason":"..."}
{"ts":"2026-07-01T10:00:10Z","host":"codex","session_id":"def","tool_name":"apply_patch","cmd":"*** Begin Patch\n...","action":"deny","reason":"..."}
```

For `apply_patch` calls the `cmd` field contains the full raw patch text.

## Complete example configuration for a dual-host setup

```yaml
version: 1

default_action: deny

audit_log: "~/.claude/hookguard-audit.jsonl"

opaque_execution_guard:
  action: ask

powershell_opaque_execution_guard:
  action: ask

# Required for apply_patch calls from Codex CLI.
patch_opaque_execution_guard:
  action: ask

rules:

  # ── git ──────────────────────────────────────────────────────────────────
  - tool: git
    action: allow

  - tool: git
    subcommand: push
    deny_flags: ["--force", "--force-with-lease", "-f"]
    action: deny
    reason: "force-push rewrites remote history"

  - tool: git
    subcommand: commit
    deny_flags: ["--no-verify", "-n"]
    action: deny
    reason: "--no-verify skips pre-commit hooks"

  # ── sensitive files ───────────────────────────────────────────────────────
  # These path rules also apply to apply_patch Patch-Segments under Codex.
  - tools: ["Read"]
    path: "**/.env*"
    action: deny
    reason: "reading .env files may leak secrets"

  - tools: ["Write"]
    path: "**/.env*"
    action: deny
    reason: "writing .env files may expose secrets"

  - tools: ["Edit", "Write"]
    path: "**/secrets/**"
    action: deny
    reason: "editing files under secrets/ is not allowed"

  # ── common tools ─────────────────────────────────────────────────────────
  - tool: ls
    action: allow
  - tool: cat
    action: allow
  - tool: grep
    action: allow
  - tool: find
    action: allow
  - tool: make
    action: allow
  - tool: go
    action: allow
  - tool: npm
    action: allow

  - tool: rm
    action: ask
    reason: "always confirm rm"

  # ── PowerShell cmdlets ────────────────────────────────────────────────────
  # Under Codex on Windows these rules also apply to Bash-reported commands
  # that hookguard reroutes through the PowerShell parser.
  - cmdlet: Remove-Item
    action: ask
    reason: "always confirm Remove-Item"

  - cmdlet: Invoke-WebRequest
    action: ask
    reason: "network egress"
```
