# Integrating hookguard with Claude Code

hookguard runs as a Claude Code `PreToolUse` hook. Claude Code invokes it once per tool call, passing a JSON payload on stdin and reading the allow/deny/ask decision from stdout.

## How the hook protocol works

Before executing any tool call, Claude Code:

1. Serialises the call to a JSON object and writes it to the hook's stdin.
2. Runs the hook binary and waits for it to exit.
3. Reads a JSON object from stdout.
4. Acts on `hookSpecificOutput.permissionDecision`:
   - `allow` — execute the tool call.
   - `deny` — block it; show `permissionDecisionReason` to the user.
   - `ask` — pause and ask the user for confirmation before proceeding.

The hook must exit with code `0` when returning structured JSON. Exit code `2` causes Claude Code to treat the entire stdout as a plain-text block reason.

> **Important:** `deny` decisions from a `PreToolUse` hook are enforced even when Claude Code is running with `--dangerously-skip-permissions` or `bypassPermissions` mode. This makes hookguard's deny rules a hard enforcement layer that cannot be bypassed by the agent.

## JSON payload shape

Claude Code sends a payload like this on stdin for every tool call:

```json
{
  "session_id": "abc123",
  "cwd": "/Users/dev/myproject",
  "tool_name": "Bash",
  "tool_input": {
    "command": "git push --force origin main"
  }
}
```

For file tool calls (`Read`, `Edit`, `Write`, …) `tool_input` contains `file_path` instead of `command`:

```json
{
  "session_id": "abc123",
  "cwd": "/Users/dev/myproject",
  "tool_name": "Read",
  "tool_input": {
    "file_path": "/Users/dev/myproject/.env"
  }
}
```

hookguard responds with:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "force-push rewrites remote history and bypasses branch protections"
  }
}
```

## Registering the hook

Claude Code hook registration lives in `settings.json`. There are three scopes:

| Scope | File location | Who it applies to |
|-------|--------------|-------------------|
| Personal | `~/.claude/settings.json` | You only, all projects |
| Project | `.claude/settings.json` (in repo root) | Everyone who checks out this repo |
| Managed | system-level path (see below) | Organisation-wide, cannot be overridden |

### Personal setup

Add to `~/.claude/settings.json`:

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
      },
      {
        "matcher": "PowerShell",
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

The `Bash` matcher covers all Bash tool calls. The `PowerShell` matcher covers PowerShell tool calls (Windows). Register both — without the `PowerShell` matcher hookguard never sees PowerShell calls, leaving them as an unguarded bypass of the policy.

If hookguard is not on your `$PATH`, use the full path:

```json
"command": "/usr/local/bin/hookguard"
```

To specify a non-default policy file:

```json
"command": "HOOKGUARD_POLICY=/path/to/hookguard.yaml hookguard"
```

### Project-level setup

Commit `.claude/settings.json` to your repository so the hook applies to every team member who opens the project in Claude Code:

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
      },
      {
        "matcher": "PowerShell",
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

Each developer still needs the `hookguard` binary installed and their own `~/.claude/hookguard.yaml` in place. For a consistent team policy, commit the shared policy file and point to it with `HOOKGUARD_POLICY`:

```json
"command": "HOOKGUARD_POLICY=$PWD/.claude/hookguard.yaml hookguard"
```

`$PWD` is expanded by the shell at hook invocation time to the current working directory (the project root).

### Enterprise / managed settings

Managed settings are applied organisation-wide and **cannot be overridden** by user or project settings. They are suitable for enforcing a minimum security baseline across all developer machines.

| Platform | Managed settings path |
|----------|-----------------------|
| macOS | `/Library/Application Support/Claude/managed_settings.json` |
| Linux | `/etc/claude-code/managed_settings.json` |

Deploy the shared policy file to a protected path (e.g. `/etc/claude-code/hookguard.yaml`) and reference it from managed settings:

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

## Covered tool types

The following tool names are sent by Claude Code and can be matched in hookguard policy rules:

| `tool_name` | What it represents | Key `tool_input` fields |
|-------------|-------------------|------------------------|
| `Bash` | Shell command execution | `command` (string) |
| `PowerShell` | PowerShell command (Windows) | `command` (string) |
| `Read` | Read a file | `file_path` (string) |
| `Edit` | Edit a file (replace text) | `file_path` (string) |
| `Write` | Write / create a file | `file_path` (string) |
| `Glob` | File glob search | `pattern` (string) |
| `Grep` | Text search in files | `pattern`, `path` (strings) |
| `LS` | List directory contents | `path` (string) |
| `WebFetch` | Fetch a URL | `url` (string) |
| `WebSearch` | Web search | `query` (string) |

Match any of these by name using the `tools:` sugar field or a raw `when:` expression:

```yaml
# Block web fetches to external URLs
- tools: ["WebFetch"]
  when: '!tool_input.url.startsWith("https://internal.example.com")'
  action: deny
  reason: "only internal URLs are permitted"
```

## How Bash commands are parsed

When the `tool_name` is `Bash`, hookguard:

1. **Checks for opaque constructs** first. If the command contains `eval`, `exec`, `source`, `sh -c`, `xargs`, command substitution `$(...)`, arithmetic `$(( ))`, or control structures (`if`/`while`/`for`/`case`), the `opaque_execution_guard` fires immediately — no rule evaluation occurs for this call.

2. **Splits the command into segments.** A compound command like `git add . && git commit -m "msg" && git push --force` produces three segments. Each is evaluated independently.

3. **Evaluates every segment against all rules.** The most severe action across all segments wins. A single `deny`-triggering segment in a long pipeline denies the whole command.

## How PowerShell commands are parsed

When the `tool_name` is `PowerShell`, hookguard:

1. **Checks for opaque constructs** first via the `powershell_opaque_execution_guard`. Triggers include `Invoke-Expression`/`iex`, dot-sourcing, dynamic `& $var` call-operator targets, `-EncodedCommand`, `Add-Type`, and control structures.

2. **Resolves aliases** to their canonical `Verb-Noun` cmdlet name (`rm` → `Remove-Item`, `curl` → `Invoke-WebRequest`, `kill` → `Stop-Process`, etc.).

3. **Splits into PowerShell-Segments** on `|` and `;`. Each segment carries the cmdlet name, named parameters with their values, switches (value-less flags), and positional arguments.

4. **Evaluates every segment.** The most severe action across all segments wins.

## Verifying the setup

Test manually from a terminal — hookguard reads from stdin and writes to stdout, independent of Claude Code:

```bash
# Should allow
echo '{"session_id":"test","cwd":".","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | HOOKGUARD_POLICY=~/.claude/hookguard.yaml hookguard | jq .

# Should deny
echo '{"session_id":"test","cwd":".","tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}' \
  | HOOKGUARD_POLICY=~/.claude/hookguard.yaml hookguard | jq .

# Should deny (sensitive file)
echo '{"session_id":"test","cwd":".","tool_name":"Read","tool_input":{"file_path":"/home/user/.env"}}' \
  | HOOKGUARD_POLICY=~/.claude/hookguard.yaml hookguard | jq .
```

## Policy file not found

If hookguard cannot read the policy file, it responds with `ask` by default (so the user is neither silently blocked nor silently allowed), and includes the error in the reason string. Set `HOOKGUARD_FAIL_MODE=deny` to block all calls when the policy is unavailable — appropriate for automated or CI environments.
