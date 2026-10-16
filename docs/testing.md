# Testing policies with `hookguard test`

`hookguard test <testfile>` runs a plain-text collection of expected policy
decisions against a loaded `hookguard.yaml`, so you can catch regressions
before deploying a policy change — instead of manually piping JSON payloads
through `hookguard | jq` (see [getting-started.md](getting-started.md)) for
every case you care about.

```bash
hookguard test policy-tests.txt --policy config/hookguard.yaml
```

## Testfile syntax

```
# Comments and blank lines are ignored
Bash: git commit -m "Test Commit" --no-verify -> deny
Bash: git --no-verify commit -m "Test" -> deny
Bash: git -n commit -m "Test" -> deny
Bash: git push --force origin main -> deny
PowerShell: Remove-Item -Recurse -Force C:\ -> ask
Read: /app/.env -> deny
Write: secrets/api_key.txt -> deny
Glob: **/*.pem -> deny
Grep: password -> ask
LS: /etc -> allow
WebFetch: https://evil.example.com -> deny
WebSearch: internal roadmap 2026 -> ask
```

Each line is `<Tool>: <Value> -> <decision>`:

- **Tool prefix** is the text before the first `:` in the trimmed line. It's
  always explicit — there's no implicit default, even for `Bash`.
- **Separator**: `value` and `decision` are split on the *last* occurrence of
  ` -> ` in the rest of the line, so `->` can appear inside the value itself
  (e.g. a Bash argument) without breaking the parse.
- **Decision keyword** must be exactly `allow`, `deny`, or `ask`
  (case-sensitive).
- **Comments and blank lines**: a line that's blank after trimming, or starts
  with `#`, is skipped — it's not a test case and never causes an error.

### Supported tools

Exactly these 10, case-sensitive, mapped to the `tool_input` field they
populate:

| Tool | `tool_input` field |
|---|---|
| `Bash`, `PowerShell` | `command` |
| `Read`, `Edit`, `Write` | `file_path` |
| `Glob` | `pattern` |
| `Grep` | `pattern` (no `path` — see Limitations below) |
| `LS` | `path` |
| `WebFetch` | `url` |
| `WebSearch` | `query` |

MCP tools (names starting with `mcp__`) are supported too, see
[MCP tools](#mcp-tools) below.

`apply_patch` is intentionally **not** supported: its multi-line patch text
doesn't fit a one-line testfile format. Test `apply_patch` behavior with Go
unit tests in `cmd/hookguard/main_test.go` instead.

### MCP tools

For tools named `mcp__<server>__<tool>` the value is the complete `tool_input`
as a JSON object. An empty value means `{}`.

```text
mcp__github__get_issue:    {"owner": "afry23", "repo": "hookguard", "number": 1} -> allow
mcp__github__create_issue: {"owner": "secret-org", "title": "x"}                 -> deny
mcp__github__create_issue: {"title": "no owner given"}                           -> ask
mcp__github__list_commits: -> allow
```

A value that is not a JSON object is a parse error. Tool names outside the
list above that do not start with `mcp__` are still rejected, which catches
typos like `bash`.

## Fail-fast parsing

The whole file is parsed before any test case runs. If any line is malformed
— unknown tool, missing ` -> `, invalid decision keyword — parsing stops at
the first error, the line number and reason are printed to stderr, and the
process exits 1. **No test case runs** in that situation, so you never get a
partial, misleading PASS count from a file that has a typo further down.

## CLI

```
hookguard test <testfile> [--policy <path>] [--host claude|codex]
```

- `--policy` overrides normal policy resolution (`$HOOKGUARD_POLICY`, then
  the per-host default path).
- `--host` (default `claude`) simulates the ask-to-deny downgrade for Codex:
  an `ask`-resolving rule shows as `deny` under `--host codex`, `ask` under
  `--host claude`.

Output: one `PASS`/`FAIL line N: Tool: Value -> decision` per test case on
stdout (a `FAIL` also prints the expected vs. actual decision and the reason),
followed by `N/M passed`. Exit 0 only if every case passes, otherwise exit 1.
Setup and parse errors go to stderr with exit 1, before any test case runs.

## Example transcript

```bash
$ hookguard test policy-tests.txt --policy config/hookguard.yaml
PASS line 2: Bash: git commit -m "Test Commit" --no-verify -> deny
PASS line 3: Bash: git --no-verify commit -m "Test" -> deny
FAIL line 4: Bash: git -n commit -m "Test" -> deny
     expected deny, got allow: no rule matched (default_action=deny)
3/4 passed
$ echo "exit: $?"
exit: 1
```

## Design notes

- **Fail-fast, not best-effort.** Running the valid cases in a broken file
  and reporting the parse error alongside them would make a typo look like a
  passing test suite with one missing line, rather than a broken file. A
  testfile is validated as a whole before anything executes.
- **Reuses `decide()`, no parallel evaluator.** Every test case goes through
  the exact same `decide(hookInput, policy, host)` call that a real hook
  invocation uses in `cmd/hookguard/main.go`. There's no second,
  independently-maintained rule evaluator, opaque-guard check, segment
  splitter, or Codex downgrade logic to keep in sync with the real one.

## Limitations

A testfile line can't set `cwd`, `session_id`, `permission_mode`, `model`,
`turn_id`, `tool_use_id`, or `transcript_path` — only `tool_name` and one
`tool_input` field. `when:` rules that key off any of those fields can't be
exercised exactly through `hookguard test`; use a Go unit test (or a manual
`echo ... | hookguard | jq` call, see [getting-started.md](getting-started.md))
for those instead.
