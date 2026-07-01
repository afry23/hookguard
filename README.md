# hookguard

A CEL-driven security gateway for Claude Code's `PreToolUse` hook.
Every tool call Claude attempts to make — Bash commands, file reads/writes,
and more — is evaluated against a declarative policy before execution.

```
Claude Code (PreToolUse: Bash / Read / Edit / Write / …)
        │  JSON via stdin
        ▼
  ┌───────────────────────────────┐
  │  hookguard  (Go binary)       │
  │  1. Shell-aware tokeniser     │  ← mvdan.cc/sh/v3 (not regex, Bash only)
  │  2. Rules compiled to CEL     │  ← hookguard.yaml, cel-go
  │  3. Severity-based resolution │  ← deny > ask > allow
  │  4. Audit log (JSONL)         │
  └───────────────────────────────┘
        │  JSON via stdout
        ▼
  permissionDecision: allow | deny | ask
```

**Key properties**

- A single `rules:` list, evaluated with [CEL](https://github.com/google/cel-go),
  covers Bash segments *and* generic `tool_input` fields for Read/Edit/Write
  and any other tool.
- Shell-correct parsing via `mvdan.cc/sh/v3` — respects quoting, pipelines,
  `&&`/`||`/`;`, and reliably detects opaque constructs (`eval`, `sh -c`,
  `$(…)`, `xargs`, …).
- Combined short flags are expanded (`-rf` → `-r`, `-f`) before matching.
- When several rules match the same tool call, the most **severe** action
  wins (`deny > ask > allow`) — not the rule that appears first in the file.
- `deny` decisions from this hook survive `--dangerously-skip-permissions`
  and `bypassPermissions` mode (Claude Code PreToolUse guarantee).
- Single static binary; no interpreter runtime needed on developer machines.

---

## Build & install

**Prerequisites:** Go 1.23+

```bash
git clone https://github.com/yourorg/hookguard
cd hookguard

make install          # builds + installs to /usr/local/bin/hookguard
# or
make PREFIX=~/.local install   # install to ~/.local/bin/hookguard
```

`make build` produces a `./hookguard` binary in the project root without
installing.

---

## Configure the policy

Copy the example policy to the default location:

```bash
cp config/hookguard.yaml ~/.claude/hookguard.yaml
```

Edit `~/.claude/hookguard.yaml` to match your team's requirements.

### Schema reference

```yaml
version: 1
default_action: deny          # fallback when no rule matches
audit_log: ~/.claude/hookguard-audit.jsonl

opaque_execution_guard:
  action: ask                  # eval / sh -c / $(...) → ask user

powershell_action: ask         # blanket decision for PowerShell calls (no parsing)

rules:
  # Bash sugar: tool / subcommand / deny_flags compile to a CEL expression
  # matching Bash segments.
  - tool: git
    subcommand: push
    deny_flags: ["--force", "--force-with-lease", "-f"]
    action: deny
    reason: "force-push rewrites remote history"

  # Path sugar: tools / path compile to a CEL expression matching
  # tool_input.file_path for the listed tools.
  - tools: ["Read"]
    path: "**/.env*"
    action: deny
    reason: "reading .env files may leak secrets"

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
| `deny_flags` | Bash | Match if any of these flags is present (list both short and long forms explicitly — there is no flag-alias table) |
| `tools` | any tool | List of `tool_name` values this rule applies to, e.g. `["Read", "Edit"]` |
| `path` | Read/Edit/Write | Glob pattern matched against `tool_input.file_path` |
| `when` | any | Raw CEL boolean expression |

A rule must set exactly one of `tool` or `tools` (or rely solely on `when`),
and must have at least one condition (sugar and/or `when`).

#### CEL variable table

Available to every `when:` expression and every sugar compilation:

| Name | CEL type | Source | Notes |
|---|---|---|---|
| `tool_name` | `string` | `tool_name` from the hook payload | e.g. `"Bash"`, `"Read"` |
| `tool_input` | `dyn` (map) | decoded `tool_input` JSON object | generic, e.g. `{"file_path": "..."}` |
| `segment` | `dyn` (map) | current Bash segment (Bash only) | `{tool, subcommand, flags, args}`; zero-value map for non-Bash calls (`tool:"", subcommand:"", flags:[], args:[]`), never missing/null |
| `cwd` | `string` | `cwd` from the hook payload | |
| `session_id` | `string` | `session_id` from the hook payload | |

#### `glob(path, pattern)`

Custom CEL function backed by `github.com/bmatcuk/doublestar/v4`, e.g.
`glob(tool_input.file_path, "**/.env*")`. Argument order is `(path,
pattern)`.

A CEL **runtime error** in a rule (e.g. accessing a field absent for the
current tool) escalates that rule to action `ask` — it still participates in
severity resolution (so a `deny` elsewhere still wins), but the error can
never silently resolve to `allow`. Compile-time errors (bad CEL syntax,
malformed glob patterns, invalid sugar-field combinations) fail `Load()`
immediately.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `HOOKGUARD_POLICY` | `~/.claude/hookguard.yaml` | Override policy file path |
| `HOOKGUARD_FAIL_MODE` | `ask` | Decision when policy file is missing (`allow`/`deny`/`ask`) |

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
        "hooks": [
          {
            "type": "command",
            "command": "hookguard"
          }
        ]
      }
    ]
  }
}
```

If you installed the binary to a non-standard path, use the full path:

```json
"command": "/usr/local/bin/hookguard"
```

To pass a custom policy file:

```json
"command": "HOOKGUARD_POLICY=/etc/claude-code/hookguard.yaml hookguard"
```

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
      }
    ]
  }
}
```

---

## Audit log

Every tool call is appended to the file configured in `audit_log` as JSONL:

```jsonl
{"ts":"2026-07-01T10:00:00Z","session_id":"abc123","cwd":"/app","tool_name":"Bash","cmd":"git push --force origin main","action":"deny","reason":"force-push rewrites remote history"}
{"ts":"2026-07-01T10:00:05Z","session_id":"abc123","cwd":"/app","tool_name":"Read","action":"deny","reason":"reading .env files may leak secrets"}
```

`cmd` is only populated for Bash tool calls.

Parse with `jq`:

```bash
# All denied calls today
jq 'select(.action=="deny")' ~/.claude/hookguard-audit.jsonl

# Summary by action
jq -r '.action' ~/.claude/hookguard-audit.jsonl | sort | uniq -c
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

---

## Development

```bash
make test     # run all unit tests
make lint     # requires golangci-lint

# Manually test the hook by piping example Claude Code JSON:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .

echo '{"tool_name":"Read","tool_input":{"file_path":"/app/.env"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .

echo '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse -Force C:\\"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .
```

Expected output for the first command:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "force-push rewrites remote history and bypasses branch protections"
  }
}
```

---

## Project structure

```
hookguard/
├── cmd/hookguard/main.go            # entry point: stdin→decision→stdout
├── internal/
│   ├── shell/
│   │   ├── tokenizer.go            # shell-aware command parser
│   │   └── tokenizer_test.go
│   ├── policy/
│   │   ├── policy.go               # Rule/Policy types, Load, Evaluate
│   │   ├── cel_env.go              # CEL environment + glob() function
│   │   ├── sugar.go                # sugar-field validation + CEL compilation
│   │   └── policy_test.go
│   └── audit/
│       └── audit.go                # append-only JSONL logger
├── config/
│   └── hookguard.yaml              # example policy (copy to ~/.claude/)
├── Makefile
└── README.md
```
