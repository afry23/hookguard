# hookguard.yaml Configuration Reference

hookguard is controlled by a single YAML file. Every top-level key is described below.

## File location

hookguard resolves the policy path in this order:

1. `$HOOKGUARD_POLICY` environment variable (if set)
2. `~/.claude/hookguard.yaml` — user-level, personal developer setup

To use a custom path at invocation time:

```bash
HOOKGUARD_POLICY=/etc/myorg/hookguard.yaml hookguard
```

## Top-level keys

```yaml
version: 1

default_action: deny

audit_log: "~/.claude/hookguard-audit.jsonl"

opaque_execution_guard:
  action: ask

powershell_opaque_execution_guard:
  action: ask

rules:
  - …
```

### `version`

Schema version. Currently always `1`. Required.

---

### `default_action`

The fallback decision when **no rule in `rules:` matches** a tool call.

| Value | Meaning |
|-------|---------|
| `deny` | Block unlisted calls. Secure default — recommended for production. |
| `ask` | Escalate unlisted calls to the user for confirmation. |
| `allow` | Permit unlisted calls silently. Only appropriate for very permissive setups. |

`deny` is the recommended default. Any tool or path not explicitly covered by a rule will be blocked, which forces the policy author to consciously allow operations rather than relying on a catch-all.

---

### `audit_log`

Path to an append-only JSONL file. Every tool call and its decision is recorded here. Set to `""` (empty string) to disable.

A leading `~/` is expanded to the user's home directory.

```yaml
audit_log: "~/.claude/hookguard-audit.jsonl"
```

See [Audit log format](#audit-log-format) below for the record schema and example `jq` queries.

---

### `opaque_execution_guard`

Controls what happens when a **Bash command** contains a construct that cannot be safely decomposed into segments for static analysis. This guard fires **before** rule evaluation.

Constructs that trigger it:
- `eval`
- `exec`
- `source` / `.`
- `sh -c '…'` / `bash -c '…'`
- `xargs`
- Command substitution `$(...)`
- Arithmetic commands `$(( ))`
- Control structures: `if`, `while`, `for`, `case`

```yaml
opaque_execution_guard:
  action: ask   # or deny
```

`ask` is the recommended value: it escalates to the user instead of silently allowing potentially dangerous constructs. Set to `deny` in unattended CI pipelines.

---

### `powershell_opaque_execution_guard`

The PowerShell equivalent of `opaque_execution_guard`. Fires before rule evaluation when a PowerShell command cannot be safely decomposed into cmdlet segments. Configured separately because the two parsers are independent implementations.

Constructs that trigger it:
- `Invoke-Expression` / `iex`
- Dot-sourcing (`. ./script.ps1`)
- Dynamic call-operator targets (`& $variable`)
- `-EncodedCommand`
- `Add-Type`
- Control structures: `if`, `while`, `for`, `foreach`, `switch`, `do`, `try`, `catch`, `finally`

```yaml
powershell_opaque_execution_guard:
  action: ask   # or deny
```

---

## `rules:` list

The `rules:` list is the heart of the policy. Each entry is a **rule** that matches a tool call via **sugar fields**, a raw `when:` CEL expression, or both (ANDed together), and resolves to an `action` if it matches.

**Severity resolution:** when multiple rules match the same tool call, the most severe action wins — `deny(2) > ask(1) > allow(0)` — regardless of the rules' order in the file.

### Rule skeleton

```yaml
rules:
  - tool: git              # sugar field (Bash)
    subcommand: push       # sugar field (Bash)
    deny_flags:            # sugar field (Bash or PowerShell)
      - "--force"
      - "-f"
    action: deny
    reason: "force-push rewrites remote history"
```

Every rule must have:
- At least one condition: one or more sugar fields, a `when:` expression, or both.
- An `action`: `allow`, `deny`, or `ask`.
- Optionally a `reason` string shown to the agent (and the user) when the action is `deny` or `ask`.

---

### Sugar fields

Sugar fields compile deterministically to an equivalent CEL expression at policy load time, so common cases do not require hand-written CEL.

#### Bash sugar

Use these for Bash tool calls. They match against the parsed **segment** (one command unit after splitting on `|`, `&&`, `;`, etc.).

| Field | Type | Description |
|-------|------|-------------|
| `tool` | string | The primary executable, e.g. `"git"`, `"rm"`, `"docker"`. |
| `subcommand` | string | The first non-flag argument, e.g. `"push"`, `"commit"`. Requires `tool`. |
| `deny_flags` | list of strings | Match if **any** of these flags is present in the segment. Combined short flags are pre-expanded (`-rf` → `-r`, `-f`). |

```yaml
# Deny git force-push
- tool: git
  subcommand: push
  deny_flags: ["--force", "--force-with-lease", "-f"]
  action: deny
  reason: "force-push rewrites remote history"

# Ask for confirmation before any rm
- tool: rm
  action: ask
  reason: "always require confirmation for rm"
```

`tool` without `subcommand` or `deny_flags` matches **every invocation** of that executable:

```yaml
- tool: curl
  action: ask
  reason: "network egress; ask before sending data out"
```

#### PowerShell sugar

Use these for PowerShell tool calls. They match against the parsed **PowerShell-Segment** (one cmdlet invocation after splitting on `|`, `;`, etc.).

| Field | Type | Description |
|-------|------|-------------|
| `cmdlet` | string | The canonical `Verb-Noun` cmdlet name, e.g. `"Remove-Item"`. Built-in aliases (`rm`, `ri`, `del`, `erase`, `rd`, `rmdir`) are resolved to their canonical form before matching. |
| `deny_flags` | list of strings | When used with `cmdlet`: match if any of these parameter **names** or switch **names** is present. Values are not compared. List both short and long forms explicitly — there is no alias table for parameter names. |

```yaml
# Ask before Remove-Item (also matches rm, ri, del, etc.)
- cmdlet: Remove-Item
  action: ask
  reason: "always require confirmation for Remove-Item"

# Ask when Stop-Process is used with -Force
- cmdlet: Stop-Process
  deny_flags: ["Force"]
  action: ask
  reason: "force-stopping a process can lose unsaved state"
```

#### Path sugar (Read / Edit / Write)

Use these to match file-level operations by the tool name and a glob pattern on the file path.

| Field | Type | Description |
|-------|------|-------------|
| `tools` | list of strings | Tool names this rule applies to, e.g. `["Read", "Edit", "Write"]`. |
| `path` | glob string | Matched against `tool_input.file_path` using `github.com/bmatcuk/doublestar/v4` glob semantics (`**` crosses directory boundaries). Requires `tools`. |

```yaml
# Block reading .env files
- tools: ["Read"]
  path: "**/.env*"
  action: deny
  reason: "reading .env files may leak secrets"

# Block editing anything under secrets/
- tools: ["Edit", "Write"]
  path: "**/secrets/**"
  action: deny
  reason: "editing files under secrets/ is not allowed"
```

`tools` without `path` matches every call to those tools regardless of path:

```yaml
- tools: ["Read", "Edit", "Write"]
  action: ask
```

---

### `when:` — raw CEL expressions

For cases where sugar fields are not expressive enough, write a raw [CEL](https://github.com/google/cel-go) boolean expression in the `when:` field. It is ANDed with any sugar fields present on the same rule.

```yaml
# Deny reading SSH private keys regardless of path sugar
- tools: ["Read"]
  when: 'tool_input.file_path.matches("id_rsa$")'
  action: deny
  reason: "reading SSH private keys is not allowed"

# Deny git config --global or core.hooksPath manipulation
- tool: git
  subcommand: config
  when: >
    segment.args.exists(a, a.matches("core\\.hooksPath")) ||
    segment.flags.exists(f, f == "--global")
  action: deny
  reason: "overriding core.hooksPath or writing --global config is a hook-bypass technique"
```

#### CEL variable table

All variables listed below are available in every `when:` expression and in the CEL expressions generated from sugar fields.

| Variable | CEL type | Source | Notes |
|----------|----------|--------|-------|
| `tool_name` | `string` | hook payload `tool_name` | e.g. `"Bash"`, `"Read"`, `"PowerShell"` |
| `tool_input` | `dyn` (map) | hook payload `tool_input` | generic map, e.g. `{"file_path": "..."}` or `{"command": "..."}` |
| `segment` | `dyn` (map) | current Bash segment | `{tool, subcommand, flags, args}`; zero-value map for non-Bash calls — never missing or null |
| `ps_segment` | `dyn` (map) | current PowerShell segment | `{cmdlet, parameters, switches, args}`; `parameters` is a map of name→value; zero-value map for non-PowerShell calls, never missing or null |
| `cwd` | `string` | hook payload `cwd` | working directory of the agent |
| `session_id` | `string` | hook payload `session_id` | |

**`segment` map fields:**

| Field | Type | Description |
|-------|------|-------------|
| `segment.tool` | string | primary executable, e.g. `"git"` |
| `segment.subcommand` | string | first non-flag arg, e.g. `"push"` |
| `segment.flags` | list of strings | all flags, short flags pre-expanded |
| `segment.args` | list of strings | non-flag positional arguments |

**`ps_segment` map fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ps_segment.cmdlet` | string | canonical cmdlet name, aliases resolved |
| `ps_segment.parameters` | map string→string | named parameters with a value, e.g. `{"Uri": "https://..."}` |
| `ps_segment.switches` | list of strings | named parameters with no value, e.g. `["Force", "Recurse"]` |
| `ps_segment.args` | list of strings | positional (unnamed) arguments |

#### `glob(path, pattern)` function

A custom CEL function backed by `github.com/bmatcuk/doublestar/v4`. Use it in `when:` expressions when the path sugar field is not sufficient.

```
glob(tool_input.file_path, "**/.env*")
```

Argument order: `(path, pattern)`.

#### CEL error handling

A CEL **runtime error** in a rule (e.g. accessing `segment.tool` when the call is not Bash) escalates that rule to action `ask`. It still participates in severity resolution — a `deny` from another rule still wins — but the error can never silently resolve to `allow`. Compile-time errors (bad CEL syntax, invalid glob patterns, invalid sugar-field combinations) cause `Load()` to fail immediately with a descriptive error message.

---

### Sugar-field validation rules

hookguard rejects invalid rule combinations at load time:

| Violation | Error |
|-----------|-------|
| `tool` and `tools` both set | `rule has both 'tool' and 'tools' set` |
| `tool` and `cmdlet` both set | `rule has both 'tool' and 'cmdlet' set` |
| `cmdlet` and `tools` both set | `rule has both 'cmdlet' and 'tools' set` |
| `subcommand` without `tool` | `rule sets 'subcommand' without 'tool'` |
| `deny_flags` without `tool` or `cmdlet` | `rule sets 'deny_flags' without 'tool' or 'cmdlet'` |
| `path` without `tools` | `rule sets 'path' without 'tools'` |
| No condition at all | `rule has no condition (no 'tool', 'cmdlet', 'tools', or 'when')` |

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOOKGUARD_POLICY` | `~/.claude/hookguard.yaml` | Override the policy file path. |
| `HOOKGUARD_FAIL_MODE` | `ask` | Decision when the policy file is missing or unreadable. Accepts `allow`, `deny`, `ask`. Set to `deny` for strict CI pipelines. |

---

## Audit log format

Each entry is a JSON object on its own line (JSONL):

```jsonl
{"ts":"2026-07-01T10:00:00Z","session_id":"abc123","cwd":"/app","tool_name":"Bash","cmd":"git push --force origin main","action":"deny","reason":"force-push rewrites remote history and bypasses branch protections"}
{"ts":"2026-07-01T10:00:05Z","session_id":"abc123","cwd":"/app","tool_name":"Read","action":"deny","reason":"reading .env files may leak secrets"}
```

| Field | Present when | Description |
|-------|-------------|-------------|
| `ts` | always | RFC3339 timestamp |
| `session_id` | always | agent session identifier |
| `cwd` | always | working directory at time of call |
| `tool_name` | always | e.g. `"Bash"`, `"Read"`, `"PowerShell"` |
| `cmd` | `tool_name` is `Bash` or `PowerShell` | the raw command string |
| `action` | always | `allow`, `deny`, or `ask` |
| `reason` | always | human-readable reason string |

### Useful `jq` queries

```bash
# All denied calls
jq 'select(.action=="deny")' ~/.claude/hookguard-audit.jsonl

# Summary by action
jq -r '.action' ~/.claude/hookguard-audit.jsonl | sort | uniq -c

# All blocked Bash commands
jq 'select(.tool_name=="Bash" and .action=="deny") | .cmd' ~/.claude/hookguard-audit.jsonl

# Events from a specific session
jq --arg s "abc123" 'select(.session_id==$s)' ~/.claude/hookguard-audit.jsonl
```

---

## Annotated example policy

The complete example below is the shipped `config/hookguard.yaml`. It demonstrates all major sugar patterns.

```yaml
version: 1

default_action: deny

audit_log: "~/.claude/hookguard-audit.jsonl"

opaque_execution_guard:
  action: ask

powershell_opaque_execution_guard:
  action: ask

rules:

  # ── git ──────────────────────────────────────────────────────────────────
  # Allow git in general; restrict dangerous subcommands below.
  - tool: git
    action: allow

  - tool: git
    subcommand: push
    deny_flags: ["--force", "--force-with-lease", "-f"]
    action: deny
    reason: "force-push rewrites remote history and bypasses branch protections"

  - tool: git
    subcommand: commit
    deny_flags: ["--no-verify", "-n"]
    action: deny
    reason: "--no-verify skips pre-commit and commit-msg hooks"

  - tool: git
    subcommand: tag
    deny_flags: ["--delete", "-d"]
    action: deny
    reason: "deleting tags is destructive"

  - tool: git
    subcommand: config
    action: ask
    reason: "git config can permanently alter the global git setup"

  # The more specific deny below wins over the ask above (severity resolution).
  - tool: git
    subcommand: config
    when: >
      segment.args.exists(a, a.matches("core\\.hooksPath")) ||
      segment.flags.exists(f, f == "--global")
    action: deny
    reason: "overriding core.hooksPath or writing --global config is a hook-bypass technique"

  # ── rm ───────────────────────────────────────────────────────────────────
  - tool: rm
    action: ask
    reason: "always require confirmation for rm"

  # ── curl / wget ──────────────────────────────────────────────────────────
  - tool: curl
    action: ask
    reason: "network egress; ask before sending data out"

  - tool: wget
    action: ask
    reason: "network egress; ask before sending data out"

  # ── docker ───────────────────────────────────────────────────────────────
  # Ask by default, but allow specific read-only subcommands.
  # The `when` condition here avoids the read-only allow rules being shadowed
  # by this broader ask (severity resolution would pick ask over allow).
  - tool: docker
    when: '!(segment.subcommand in ["ps", "images", "build", "logs", "inspect"])'
    action: ask
    reason: "docker commands can affect the host; ask by default"

  - tool: docker
    subcommand: run
    deny_flags: ["--privileged"]
    action: deny
    reason: "--privileged grants full host access"

  - tool: docker
    subcommand: run
    when: >
      segment.args.exists(a, a.matches("^/$")) ||
      segment.args.exists(a, a.matches("/var/run/docker\\.sock"))
    action: deny
    reason: "mounting the root filesystem or the Docker socket is a privilege-escalation vector"

  - tool: docker
    subcommand: build
    action: allow

  - tool: docker
    subcommand: ps
    action: allow

  - tool: docker
    subcommand: images
    action: allow

  - tool: docker
    subcommand: logs
    action: allow

  - tool: docker
    subcommand: inspect
    action: allow

  # ── npm ──────────────────────────────────────────────────────────────────
  - tool: npm
    action: allow

  - tool: npm
    subcommand: publish
    action: ask
    reason: "publishing to a registry is irreversible"

  # ── go ───────────────────────────────────────────────────────────────────
  - tool: go
    action: allow

  - tool: go
    subcommand: generate
    action: ask
    reason: "go:generate can run arbitrary programs"

  # ── common unix tools ────────────────────────────────────────────────────
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
  # … etc.

  - tool: sh
    action: ask
  - tool: bash
    action: ask

  # ── PowerShell cmdlets ───────────────────────────────────────────────────
  - cmdlet: Remove-Item
    action: ask
    reason: "always require confirmation for Remove-Item"

  - cmdlet: Invoke-WebRequest
    action: ask
    reason: "network egress; ask before sending data out"

  - cmdlet: Stop-Process
    deny_flags: ["Force"]
    action: ask
    reason: "force-stopping a process can lose unsaved state"

  # ── sensitive file paths (Read / Edit / Write) ───────────────────────────
  - tools: ["Read"]
    path: "**/.env*"
    action: deny
    reason: "reading .env files may leak secrets"

  - tools: ["Edit", "Write"]
    path: "**/secrets/**"
    action: deny
    reason: "editing files under secrets/ is not allowed"

  # ── raw when: example ────────────────────────────────────────────────────
  - tools: ["Read"]
    when: 'tool_input.file_path.matches("id_rsa$")'
    action: deny
    reason: "reading SSH private keys is not allowed"
```
