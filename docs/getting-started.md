# Getting Started with hookguard

hookguard is a security gateway for AI coding agents. It intercepts every tool call the agent attempts — Bash commands, file reads and writes, PowerShell cmdlets — and evaluates it against a declarative YAML policy before the agent is allowed to execute it.

```
AI agent (PreToolUse: Bash / PowerShell / Read / Edit / Write / …)
        │  JSON via stdin
        ▼
  ┌───────────────────────────────────────┐
  │  hookguard  (Go binary)               │
  │  1. Shell-aware tokenizer             │  ← mvdan.cc/sh (Bash) / internal (PowerShell)
  │  2. Rules compiled to CEL             │  ← hookguard.yaml, cel-go
  │  3. Severity-based resolution         │  ← deny > ask > allow
  │  4. Audit log (JSONL)                 │
  └───────────────────────────────────────┘
        │  JSON via stdout
        ▼
  permissionDecision: allow | deny | ask
```

## Prerequisites

- Go 1.23 or later
- Supported agents: Claude Code; OpenAI Codex CLI (in development — see [integration-codex.md](integration-codex.md))

## Installation

```bash
git clone <repo-url>
cd hookguard

# Build and install to /usr/local/bin
make install

# Or install to a different prefix
make PREFIX=~/.local install

# Build only, without installing
make build
```

The resulting binary is `hookguard`. It has no runtime dependencies — no interpreter, no managed runtime needed on developer machines. Cold-start latency is in the low single-digit milliseconds.

## Set up the policy file

hookguard requires a YAML policy file. The bundled example is a good starting point:

```bash
cp config/hookguard.yaml ~/.claude/hookguard.yaml
```

By default hookguard looks for the policy at `~/.claude/hookguard.yaml`. Override the path with the `HOOKGUARD_POLICY` environment variable.

Full configuration reference: [configuration.md](configuration.md)

## Quick smoke test

```bash
# Allowed command
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .

# Blocked command (force-push)
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .

# Blocked file read
echo '{"tool_name":"Read","tool_input":{"file_path":"/app/.env"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .

# PowerShell cmdlet
echo '{"tool_name":"PowerShell","tool_input":{"command":"Remove-Item -Recurse -Force C:\\"}}' \
  | HOOKGUARD_POLICY=config/hookguard.yaml ./hookguard | jq .
```

Expected output for the force-push test:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "force-push rewrites remote history and bypasses branch protections"
  }
}
```

To check a whole collection of expected decisions at once instead of piping
JSON by hand, use `hookguard test <testfile>` — see [testing.md](testing.md).

## Key properties

**Severity wins, not order.** When multiple rules match a single tool call, the most restrictive action wins (`deny > ask > allow`) regardless of the rules' position in the file.

**`deny` survives `--dangerously-skip-permissions`.** Claude Code guarantees that `deny` decisions from a `PreToolUse` hook apply even when the agent runs in bypass-permissions mode.

**Shell-correct parsing.** Bash commands are parsed via `mvdan.cc/sh/v3` — quoting, pipelines, `&&`/`||`/`;`, and combined short flags (`-rf` → `-r`, `-f`) are handled correctly. PowerShell is handled by a dedicated hand-written tokenizer that resolves built-in aliases (`rm`/`ri` → `Remove-Item`, etc.) to canonical cmdlet names before matching.

**Opaque execution guard.** Commands that cannot be safely analyzed statically (`eval`, `sh -c`, `$(...)`, `Invoke-Expression`, …) are intercepted before rule evaluation begins, via a separate configurable guard.

## Project structure

```
hookguard/
├── cmd/hookguard/main.go            # entry point: stdin → decision → stdout
├── internal/
│   ├── shell/
│   │   ├── tokenizer.go            # Bash parser (mvdan.cc/sh)
│   │   └── tokenizer_test.go
│   ├── powershell/
│   │   ├── parser.go               # hand-written PowerShell 7+ tokenizer
│   │   └── parser_test.go
│   ├── policy/
│   │   ├── policy.go               # Rule/Policy types, Load, Evaluate
│   │   ├── cel_env.go              # CEL environment + glob() function
│   │   ├── sugar.go                # sugar-field validation + CEL compilation
│   │   └── policy_test.go
│   └── audit/
│       └── audit.go                # append-only JSONL logger
├── config/
│   └── hookguard.yaml              # example policy (copy to ~/.claude/)
├── docs/
│   ├── adr/                        # Architecture Decision Records
│   ├── getting-started.md          # this document
│   ├── configuration.md            # policy configuration reference
│   ├── integration-claude-code.md  # Claude Code integration guide
│   └── integration-codex.md        # OpenAI Codex CLI integration guide
├── Makefile
└── README.md
```

## Development

```bash
make test     # run all unit tests
make lint     # run golangci-lint (must be installed separately)
make build    # compile the binary
make clean    # remove build artifacts
```
