# ctool-gate

A YAML-driven security gateway for Claude Code's `PreToolUse` hook.  
Every Bash command Claude attempts to run is evaluated against a declarative
policy before execution.

```
Claude Code (PreToolUse: Bash)
        │  JSON via stdin
        ▼
  ┌─────────────────────────────┐
  │  ctool-gate  (Go binary)    │
  │  1. Shell-aware tokeniser   │  ← mvdan.cc/sh/v3 (not regex)
  │  2. Segment → policy match  │  ← gate.yaml
  │  3. Audit log (JSONL)       │
  └─────────────────────────────┘
        │  JSON via stdout
        ▼
  permissionDecision: allow | deny | ask
```

**Key properties**

- Shell-correct parsing via `mvdan.cc/sh/v3` — respects quoting, pipelines,
  `&&`/`||`/`;`, and reliably detects opaque constructs (`eval`, `sh -c`,
  `$(…)`, `xargs`, …).
- Combined short flags are expanded (`-rf` → `-r`, `-f`) before matching.
- Flag alias tables map short → long form so deny rules only need the
  canonical form.
- `deny` decisions from this hook survive `--dangerously-skip-permissions`
  and `bypassPermissions` mode (Claude Code PreToolUse guarantee).
- Single static binary; no interpreter runtime needed on developer machines.

---

## Build & install

**Prerequisites:** Go 1.22+

```bash
git clone https://github.com/yourorg/ctool-gate
cd ctool-gate

make install          # builds + installs to /usr/local/bin/ctool-gate
# or
make PREFIX=~/.local install   # install to ~/.local/bin/ctool-gate
```

`make build` produces a `./ctool-gate` binary in the project root without
installing.

---

## Configure the policy

Copy the example policy to the default location:

```bash
cp config/gate.yaml ~/.claude/gate.yaml
```

Edit `~/.claude/gate.yaml` to match your team's requirements.  
The full schema is documented in the file itself.

### Quick reference

```yaml
version: 1
default_action: deny          # unknown tools are blocked
audit_log: ~/.claude/gate-audit.jsonl

flag_aliases:
  git:
    push:  { "-f": "--force" }
    commit: { "-n": "--no-verify" }

opaque_execution_guard:
  action: ask                 # eval / sh -c / $(...) → ask user

tools:
  git:
    default_action: allow
    subcommands:
      push:
        deny_flags: ["--force", "--force-with-lease"]
      commit:
        deny_flags: ["--no-verify"]
      config:
        action: ask
        deny_args_regex: ['core\.hooksPath', '^--global$']
      "*":
        action: allow
  rm:
    default_action: ask
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `CTOOL_GATE_POLICY` | `~/.claude/gate.yaml` | Override policy file path |
| `CTOOL_GATE_FAIL_MODE` | `ask` | Decision when policy file is missing (`allow`/`deny`/`ask`) |

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
            "command": "ctool-gate"
          }
        ]
      }
    ]
  }
}
```

If you installed the binary to a non-standard path, use the full path:

```json
"command": "/usr/local/bin/ctool-gate"
```

To pass a custom policy file:

```json
"command": "CTOOL_GATE_POLICY=/etc/claude-code/gate.yaml ctool-gate"
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
            "command": "CTOOL_GATE_POLICY=/etc/claude-code/gate.yaml /usr/local/bin/ctool-gate"
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
{"ts":"2026-07-01T10:00:00Z","session_id":"abc123","cwd":"/app","cmd":"git push --force origin main","action":"deny","reason":"flag \"--force\" is denied for `git push`"}
{"ts":"2026-07-01T10:00:05Z","session_id":"abc123","cwd":"/app","cmd":"git status","action":"allow"}
```

Parse with `jq`:

```bash
# All denied commands today
jq 'select(.action=="deny")' ~/.claude/gate-audit.jsonl

# Summary by action
jq -r '.action' ~/.claude/gate-audit.jsonl | sort | uniq -c
```

---

## Bonus: reuse as a git hook

Because the policy logic is self-contained in the binary, you can run the
same rules as a `pre-push` git hook to cover manual CLI use as well:

```bash
# .git/hooks/pre-push  (or via git config core.hooksPath)
#!/usr/bin/env bash
while read local_ref local_sha remote_ref remote_sha; do
  # Reconstruct the push command and pipe through ctool-gate
  cmd="git push origin $remote_ref"
  echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$cmd\"}}" \
    | ctool-gate > /tmp/gate-result.json
  decision=$(jq -r '.hookSpecificOutput.permissionDecision' /tmp/gate-result.json)
  reason=$(jq -r '.hookSpecificOutput.permissionDecisionReason // ""' /tmp/gate-result.json)
  if [ "$decision" = "deny" ]; then
    echo "ctool-gate: push blocked — $reason" >&2
    exit 1
  fi
done
```

---

## Development

```bash
make test     # run all unit tests
make lint     # requires golangci-lint

# Manually test the hook by piping example Claude Code JSON:
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | CTOOL_GATE_POLICY=config/gate.yaml ./ctool-gate | jq .
```

Expected output for the above:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "flag \"--force\" is denied for `git push`"
  }
}
```

---

## Project structure

```
ctool-gate/
├── cmd/ctool-gate/main.go          # entry point: stdin→decision→stdout
├── internal/
│   ├── shell/
│   │   ├── tokenizer.go            # shell-aware command parser
│   │   └── tokenizer_test.go
│   ├── policy/
│   │   ├── policy.go               # YAML policy loader + evaluator
│   │   └── policy_test.go
│   └── audit/
│       └── audit.go                # append-only JSONL logger
├── config/
│   └── gate.yaml                   # example policy (copy to ~/.claude/)
├── Makefile
└── README.md
```
