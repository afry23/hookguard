# hookguard

A CEL-driven security gateway for Claude Code **and Codex CLI** `PreToolUse` hooks.
Every tool call an agent attempts to make — Bash commands, file reads/writes,
`apply_patch` edits, and more — is evaluated against a declarative policy before
execution. A single `hookguard.yaml` guards both agent CLIs.

```
Claude Code / Codex CLI (PreToolUse: Bash / PowerShell / apply_patch / Read / Edit / Write / …)
        │  JSON via stdin
        ▼
  ┌───────────────────────────────┐
  │  hookguard  (Go binary)       │
  │  1. Shell-aware tokeniser     │  ← mvdan.cc/sh/v3 (Bash) or internal/powershell (PowerShell 7+)
  │  2. Patch parser              │  ← internal/patch (Codex apply_patch → Patch-Segments)
  │  3. Rules compiled to CEL     │  ← hookguard.yaml, cel-go
  │  4. Severity-based resolution │  ← deny > ask > allow
  │  5. Audit log (JSONL)         │
  └───────────────────────────────┘
        │  JSON via stdout
        ▼
  permissionDecision: allow | deny | ask
```

**Key properties**

- A single `rules:` list, evaluated with [CEL](https://github.com/google/cel-go),
  covers Bash segments, PowerShell segments, Patch-Segments (Codex
  `apply_patch`), *and* generic `tool_input` fields for Read/Edit/Write and any
  other tool.
- Shell-correct parsing via `mvdan.cc/sh/v3` for Bash — respects quoting,
  pipelines, `&&`/`||`/`;`, and reliably detects opaque constructs (`eval`,
  `sh -c`, `$(…)`, `xargs`, …).
- PowerShell 7+ is parsed by a dedicated hand-written tokenizer
  (`internal/powershell`, no maintained Go library exists for this — see
  [ADR 0005](docs/adr/0005-hand-written-powershell-tokenizer.md)), resolving
  built-in aliases (`rm`/`ri` → `Remove-Item`, …) and reliably detecting
  opaque constructs (`Invoke-Expression`, dot-sourcing, dynamic `&`
  call-operator targets, `-EncodedCommand`, `Add-Type`, control structures).
- Codex `apply_patch` calls are decomposed into Patch-Segments (one per
  `*** Add File` / `*** Update File` / `*** Delete File` / `*** Move to:`
  section) and evaluated against existing `tools`/`path` rules as `Write` or
  `Edit` operations — no new rules needed.
- Combined short flags are expanded (`-rf` → `-r`, `-f`) before matching.
- When several rules match the same tool call, the most **severe** action
  wins (`deny > ask > allow`) — not the rule that appears first in the file.
- Codex has no interactive ask channel — `ask` decisions are automatically
  downgraded to `deny` under `hookguard codex` (see [ADR 0006](docs/adr/)).
- `deny` decisions from this hook survive `--dangerously-skip-permissions`
  and `bypassPermissions` mode (Claude Code PreToolUse guarantee).
- Single static binary; no interpreter runtime needed on developer machines.

---

## Build & install

**Prerequisites:** Go 1.23+

```bash
git clone https://github.com/afry23/hookguard
cd hookguard

make install          # builds + installs to /usr/local/bin/hookguard
# or
make PREFIX=~/.local install   # install to ~/.local/bin/hookguard
```

`make build` produces a `./hookguard` binary in the project root without
installing.

---

## Configure the policy

Copy the example policy to the default location for Claude Code:

```bash
cp config/hookguard.yaml ~/.claude/hookguard.yaml
```

For Codex CLI, copy to its default location:

```bash
cp config/hookguard.yaml ~/.codex/hookguard.yaml
```

Edit the file to match your team's requirements. The same policy file can be
shared between both hosts by setting `HOOKGUARD_POLICY` to a common path.

### Schema reference

```yaml
version: 1
default_action: deny          # fallback when no rule matches
audit_log: ~/.claude/hookguard-audit.jsonl
audit_tool_input: false        # also log tool_input (e.g. MCP arguments); may contain secrets

opaque_execution_guard:
  action: ask                  # eval / sh -c / $(...) → ask user

powershell_opaque_execution_guard:
  action: ask                  # Invoke-Expression / dot-sourcing / etc. → ask user

patch_opaque_execution_guard:
  action: ask                  # malformed apply_patch text → ask user
                               # (downgraded to deny under hookguard codex)

rules:
  # Bash sugar: tool / subcommand / deny_flags compile to a CEL expression
  # matching Bash segments.
  - tool: git
    subcommand: push
    deny_flags: ["--force", "--force-with-lease", "-f"]
    action: deny
    reason: "force-push rewrites remote history"

  # PowerShell sugar: cmdlet / deny_flags compile to a CEL expression matching
  # PowerShell segments. Built-in aliases (rm/ri → Remove-Item, etc.) are
  # resolved to the canonical cmdlet name before matching.
  - cmdlet: Remove-Item
    action: ask
    reason: "always require confirmation for Remove-Item"

  # Path sugar: tools / path compile to a CEL expression matching
  # tool_input.file_path for the listed tools. Also matches Codex apply_patch
  # segments, which are decomposed into Edit/Write operations per file.
  - tools: ["Read"]
    path: "**/.env*"
    action: deny
    reason: "reading .env files may leak secrets"

  # MCP tools (Claude Code: mcp__<server>__<tool>): `tools` accepts globs and
  # `input` constrains single tool_input keys. Unlisted keys are ignored, a
  # missing key means the rule does not apply. See docs/configuration.md#mcp-tools.
  - tools: ["mcp__github__create_*"]
    input:
      owner: ["secret-org", "archive"]
    action: deny
    reason: "no changes in protected organisations"

  # Raw `when:` — a CEL boolean expression, used when sugar isn't expressive
  # enough. ANDed with any sugar fields present on the same rule.
  - tools: ["Read"]
    when: 'tool_input.file_path.matches("id_rsa$")'
    action: deny
    reason: "reading SSH private keys is not allowed"
```

Each rule matches via **sugar fields** or a raw `when:` expression (or both,
ANDed together), and resolves to `action` if it matches. A tool call may
match several rules; the most severe `action` wins, regardless of rule order
(`deny(2) > ask(1) > allow(0)`).

#### Sugar fields

| Field | Applies to | Description |
|---|---|---|
| `tool` | Bash | Primary executable, e.g. `"git"` |
| `subcommand` | Bash | First non-flag argument, e.g. `"push"` |
| `deny_flags` | Bash or PowerShell | Bash: match if any of these flags is present. PowerShell (with `cmdlet`): match if any of these parameter or switch **names** is present, value not compared |
| `cmdlet` | PowerShell | Canonical Verb-Noun cmdlet name, e.g. `"Remove-Item"`; built-in aliases are resolved to it before matching |
| `tools` | any tool | List of `tool_name` values this rule applies to, e.g. `["Read", "Edit"]` |
| `path` | Read/Edit/Write | Glob pattern matched against `tool_input.file_path`; also matched against Codex Patch-Segments (decomposed to Edit/Write) |
| `when` | any | Raw CEL boolean expression |

A rule must set exactly one of `tool`, `cmdlet`, or `tools` (or rely solely
on `when`), and must have at least one condition (sugar and/or `when`).

#### CEL variable table

Available to every `when:` expression and every sugar compilation:

| Name | CEL type | Source | Notes |
|---|---|---|---|
| `tool_name` | `string` | `tool_name` from the hook payload | e.g. `"Bash"`, `"Read"`, `"apply_patch"` |
| `tool_input` | `dyn` (map) | decoded `tool_input` JSON object | generic, e.g. `{"file_path": "..."}` |
| `segment` | `dyn` (map) | current Bash segment (Bash only) | `{tool, subcommand, flags, args}`; zero-value for non-Bash calls |
| `ps_segment` | `dyn` (map) | current PowerShell segment (PowerShell only) | `{cmdlet, parameters, switches, args}`; zero-value for non-PowerShell calls |
| `cwd` | `string` | `cwd` from the hook payload | |
| `session_id` | `string` | `session_id` from the hook payload | |
| `model` | `string` | Codex only — model name | empty string for Claude Code |
| `permission_mode` | `string` | Codex only — e.g. `"auto"`, `"suggest"` | empty string for Claude Code |
| `turn_id` | `string` | Codex only | empty string for Claude Code |
| `tool_use_id` | `string` | Codex only | empty string for Claude Code |
| `transcript_path` | `string` | Codex only — path to session transcript | empty string for Claude Code or when null |

#### `glob(path, pattern)`

Custom CEL function backed by `github.com/bmatcuk/doublestar/v4`, e.g.
`glob(tool_input.file_path, "**/.env*")`. Argument order is `(path,
pattern)`.

A CEL **runtime error** in a rule (e.g. accessing a field absent for the
current tool) escalates that rule to action `ask` — it still participates in
severity resolution (so a `deny` elsewhere still wins), but the error can
never silently resolve to `allow` (a rule can opt out with `on_error: skip`).
Compile-time errors (bad CEL syntax,
malformed glob patterns, invalid sugar-field combinations) fail `Load()`
immediately.

Full reference for every recognized `tool_name` value and what `tool:` /
`cmdlet:` / `tools:` can be set to: [docs/tool-names.md](docs/tool-names.md).

#### Ask-to-deny downgrade (Codex)

Codex CLI has no interactive ask channel. When hookguard is invoked as
`hookguard codex`, any `ask` decision — from a matched rule, an opaque guard,
or the `HOOKGUARD_FAIL_MODE` default — is automatically downgraded to `deny`.
This applies for every `tool_name`, not just Bash. See [ADR 0006](docs/adr/).

### Environment variables

| Variable | Default (Claude) | Default (Codex) | Description |
|---|---|---|---|
| `HOOKGUARD_POLICY` | `~/.claude/hookguard.yaml` | `~/.codex/hookguard.yaml` | Override policy file path |
| `HOOKGUARD_FAIL_MODE` | `ask` | `ask` (→ deny) | Decision when policy file is missing |

---

## Register as a Claude Code hook

Add to `~/.claude/settings.json` (personal) or `.claude/settings.json`
(project, committed to version control):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "hookguard" }]
      },
      {
        "matcher": "PowerShell",
        "hooks": [{ "type": "command", "command": "hookguard" }]
      }
    ]
  }
}
```

Register both matchers on Windows: without the `PowerShell` matcher, `hookguard`
never sees PowerShell tool calls, leaving them as an unregulated bypass of
the gate ("just use PowerShell instead of Bash").

If you installed the binary to a non-standard path, use the full path:

```json
"command": "/usr/local/bin/hookguard"
```

To pass a custom policy file:

```json
"command": "HOOKGUARD_POLICY=/etc/claude-code/hookguard.yaml hookguard"
```

---

## Register as a Codex CLI hook

Add to `~/.codex/config.toml`:

```toml
[[hooks]]
  event = "pre_tool_use"
  command = "hookguard codex"
  matchers = ["Bash", "apply_patch"]
```

Codex reports all shell execution (including PowerShell on Windows) as the
`"Bash"` tool name — there is no separate `PowerShell` matcher under Codex.
hookguard detects Windows at runtime and routes `Bash` calls to the
PowerShell parser automatically.

The per-host default policy path is `~/.codex/hookguard.yaml` (see [ADR 0008](docs/adr/)).
Set `HOOKGUARD_POLICY` to share a single file between Claude Code and Codex.

---

## Invocation forms

| Command | Host | Default policy path |
|---|---|---|
| `hookguard` | Claude Code | `~/.claude/hookguard.yaml` |
| `hookguard claude` | Claude Code | `~/.claude/hookguard.yaml` |
| `hookguard codex` | Codex CLI | `~/.codex/hookguard.yaml` |
| `hookguard test <file>` | n/a (test mode) | `~/.claude/hookguard.yaml` unless `--policy`/`--host` given — see [docs/testing.md](docs/testing.md) |

---

### Enterprise / team deployment

For organisation-wide enforcement deploy via **Managed Settings** (requires
admin privileges on each machine).  Managed settings cannot be overridden by
user or project settings:

- **macOS:** `/Library/Application Support/Claude/managed_settings.json`  
- **Linux:** `/etc/claude-code/managed_settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "HOOKGUARD_POLICY=/etc/claude-code/hookguard.yaml /usr/local/bin/hookguard"
          }
        ]
      },
      {
        "matcher": "PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "HOOKGUARD_POLICY=/etc/claude-code/hookguard.yaml /usr/local/bin/hookguard"
          }
        ]
      }
    ]
  }
}
```

---

## Audit log

Every tool call is appended to the file configured in `audit_log` as JSONL:

```jsonl
{"ts":"2026-07-01T10:00:00Z","host":"claude","session_id":"abc123","cwd":"/app","tool_name":"Bash","cmd":"git push --force origin main","action":"deny","reason":"force-push rewrites remote history"}
{"ts":"2026-07-01T10:00:05Z","host":"codex","session_id":"abc123","cwd":"/app","tool_name":"apply_patch","cmd":"*** Begin Patch\n*** Add File: foo/.env\n...","action":"deny","reason":"env file read denied"}
```

`host` identifies the agent CLI (`"claude"` or `"codex"`). `cmd` is populated
for Bash, PowerShell, and `apply_patch` tool calls.

Parse with `jq`:

```bash
# All denied calls today
jq 'select(.action=="deny")' ~/.claude/hookguard-audit.jsonl

# Summary by action
jq -r '.action' ~/.claude/hookguard-audit.jsonl | sort | uniq -c

# Only Codex calls
jq 'select(.host=="codex")' ~/.claude/hookguard-audit.jsonl
```

---

## Bonus: reuse as a git hook

Because the policy logic is self-contained in the binary, you can run the
same rules as a `pre-push` git hook to cover manual CLI use as well:

```bash
# .git/hooks/pre-push  (or via git config core.hooksPath)
#!/usr/bin/env bash
while read local_ref local_sha remote_ref remote_sha; do
  # Reconstruct the push command and pipe through hookguard
  cmd="git push origin $remote_ref"
  echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$cmd\"}}" \
    | hookguard > /tmp/hookguard-result.json
  decision=$(jq -r '.hookSpecificOutput.permissionDecision' /tmp/hookguard-result.json)
  reason=$(jq -r '.hookSpecificOutput.permissionDecisionReason // ""' /tmp/hookguard-result.json)
  if [ "$decision" = "deny" ]; then
    echo "hookguard: push blocked — $reason" >&2
    exit 1
  fi
done
```

---

## Breaking change: no migration path

The unified CEL-based `rules:` schema replaces the previous `tools:` tree
(`deny_flags`/`deny_args_regex`/`flag_aliases` nested per tool/subcommand)
outright. There is no automatic migration — hookguard has no prior
users/configurations to migrate. If you need the old schema, check out a
Git tag prior to this change.

## Breaking change: PowerShell is now parsed, not blanket-asked

`powershell_action` (a single blanket `allow`/`deny`/`ask` for every
PowerShell call, no inspection performed) is replaced by real PowerShell
parsing plus `powershell_opaque_execution_guard` — see
[ADR 0005](docs/adr/0005-hand-written-powershell-tokenizer.md). This is a
hard cutover, not a validated migration: a config file that still sets
`powershell_action` will load without error (YAML silently ignores unknown
fields) but the field no longer has any effect — PowerShell calls will be
governed by real parsing, `default_action`, and
`powershell_opaque_execution_guard` instead. Migrate by replacing
`powershell_action` with `powershell_opaque_execution_guard: { action: ... }`
and adding `cmdlet:` rules for anything you want to control beyond
`default_action`.

---

## Development

```bash
make test     # run all unit tests
make lint     # requires golangci-lint

# Manually test the hook:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard claude | jq .

echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard codex | jq .

echo '{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: foo/.env\n+secret\n*** End Patch"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard codex | jq .
```

Expected output for the Codex force-push command (ask rule downgraded to deny):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "ask downgraded to deny (Codex has no ask channel): ..."
  }
}
```

---

## Project structure

```
hookguard/
├── cmd/hookguard/main.go            # entry point: parseHost → decide → stdout
├── internal/
│   ├── shell/
│   │   ├── tokenizer.go            # Bash command parser (mvdan.cc/sh)
│   │   └── tokenizer_test.go
│   ├── powershell/
│   │   ├── parser.go               # hand-written PowerShell 7+ tokenizer
│   │   └── parser_test.go
│   ├── patch/
│   │   ├── parser.go               # Codex apply_patch → Patch-Segment parser
│   │   └── parser_test.go
│   ├── policy/
│   │   ├── policy.go               # Rule/Policy types, Load, Evaluate
│   │   ├── cel_env.go              # CEL environment + glob() function
│   │   ├── sugar.go                # sugar-field validation + CEL compilation
│   │   └── policy_test.go
│   └── audit/
│       ├── audit.go                # append-only JSONL logger
│       └── audit_test.go
├── config/
│   └── hookguard.yaml              # example policy (copy to ~/.claude/ or ~/.codex/)
├── Makefile
└── README.md
```
