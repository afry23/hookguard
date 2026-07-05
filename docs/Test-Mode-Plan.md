# `hookguard test <testfile>` — test mode for policy rules

## Context

hookguard decides per tool call, via `hookguard.yaml`, whether an action gets
`allow`/`deny`/`ask`. So far this can only be checked manually by piping a
JSON payload through `echo ... | hookguard | jq` (see
`docs/getting-started.md`). That doesn't scale: there's no way to run a
collection of expected decisions as a regression test against your own
policy before deploying or changing it.

Goal: a new subcommand `hookguard test <testfile>` that validates a
plain-text file of test cases (`Tool: Value -> expected decision`) against a
loaded `hookguard.yaml` and reports PASS/FAIL per line plus a summary and a
CI-friendly exit code. This lets you check, e.g., before a merge, whether
`git commit --no-verify` really resolves to `deny`, without hand-building
the JSON envelope.

## Testfile format (finalized)

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

- **Line format**: `<Tool>: <Value> -> <decision>`. The tool prefix is
  always explicit (even for Bash — no implicit default).
- **Supported tools** (exactly these 10, case-sensitive):
  `Bash`, `PowerShell`, `Read`, `Edit`, `Write`, `Glob`, `Grep`, `LS`,
  `WebFetch`, `WebSearch`. `apply_patch` is deliberately **excluded**
  (multi-line patch text doesn't fit the one-line format, stays Go
  unit-test territory).
- **Value → `tool_input` field**:
  | Tool | Field |
  |---|---|
  | `Bash`, `PowerShell` | `command` |
  | `Read`, `Edit`, `Write` | `file_path` |
  | `Glob` | `pattern` |
  | `Grep` | `pattern` (no `path` — documented limitation) |
  | `LS` | `path` |
  | `WebFetch` | `url` |
  | `WebSearch` | `query` |
- **Decision keyword**: exactly `allow` / `deny` / `ask` (case-sensitive).
- **Separator parsing**: the tool prefix is the text before the first `:` in
  the trimmed line (tool names never contain `:`, so this is safe even when
  the value itself later contains colons, e.g. `WebFetch: https://...`).
  After that, `value`/`decision` are split on the **last** occurrence of
  ` -> ` in the remainder — this tolerates `->` inside the value (e.g. in a
  Bash argument).
- **Comments/blank lines**: lines that are empty after trimming or start
  with `#` are skipped (not a test case, not an error).
- **Malformed lines**: the whole file is parsed up front; on the first error
  (unknown tool, missing ` -> `, invalid decision keyword) the run aborts
  immediately (line number + reason on stderr, exit 1) — **no** test case
  runs in that event.

## CLI

```
hookguard test <testfile> [--policy <path>] [--host claude|codex]
```

- `--policy` overrides normal policy resolution (`$HOOKGUARD_POLICY`, then
  the per-host default path).
- `--host` (default `claude`) simulates the ask-to-deny downgrade for
  Codex — for `ask` rules, `--host codex` shows `deny`, `--host claude`
  shows `ask`.
- Output: per test case `PASS`/`FAIL line N: Tool: Value -> decision` on
  stdout (on FAIL, additionally expected vs. actual decision + reason), and
  `N/M passed` at the end. Exit 0 only if all pass, otherwise exit 1.
  Setup/parse errors go to stderr, exit 1.

## Implementation

**New file `cmd/hookguard/testmode.go`** (package `main`, reuse-based, no
new evaluation system):

```go
type testCase struct {
    Line     int
    Raw      string
    Tool     string
    Value    string
    Expected policy.Action
}
type testFileParseError struct{ Line int; Reason string }

var supportedTestTools = map[string]bool{ /* the 10 tools */ }

func parseTestFile(r io.Reader) ([]testCase, error)
func parseTestLine(raw string, lineNo int) (testCase, error)
func toolInputFor(tool, value string) map[string]any
func hostFromFlag(s string) (host, error)
func runTestMode(args []string, stdout, stderr io.Writer) int
```

`runTestMode` takes `io.Writer` instead of `os.Stdout`/`os.Stderr` directly
and returns an `int` instead of calling `os.Exit` — only `main()` calls
`os.Exit(runTestMode(...))`. This makes `testmode_test.go` testable without
a subprocess.

Every test case goes through **exactly the same pipeline as a real hook
call**: `decide(hookInput{ToolName: tc.Tool, ToolInput: toolInputFor(...)},
pol, h)` — the same function `cmd/hookguard/main.go:137` already uses in
production. No separate/parallel evaluator, no duplication of opaque-guard
detection, segment splitting, or Codex downgrade logic.

**Change to `cmd/hookguard/main.go`** — the only change to the existing
file, minimal, no subcommand framework:

```go
func main() {
	if len(os.Args) >= 2 && os.Args[1] == "test" {
		os.Exit(runTestMode(os.Args[2:], os.Stdout, os.Stderr))
	}
	runHook(parseHost(os.Args))
}
```
Plus an update to the package doc comment (lines 8-13) to add the new usage line.

**Flags** via stdlib `flag` (first use of `flag` in the repo — appropriate
for two optional flags plus one positional arg, no framework needed):
`flag.NewFlagSet("hookguard test", flag.ContinueOnError)`, `--policy`,
`--host` (validated via its own `hostFromFlag`, **not** the existing
`parseHost` — which silently defaults to `claude` on typos; `--host` must
fail loudly on an invalid value). The policy path fallback uses the
existing `resolvePolicyPath(h)`.

**New file `cmd/hookguard/testmode_test.go`**: table-driven unit tests for
`parseTestLine`/`parseTestFile` (all 10 tools, comments/blank lines, every
error case, the `->`-inside-value edge case, fail-fast behavior), plus
integration tests for `runTestMode` (all PASS, one FAIL, a broken file,
invalid `--host`, missing testfile argument, `--policy` override, default
policy resolution via `$HOOKGUARD_POLICY`, the Codex ask-downgrade case) —
mirrored on the `loadTestPolicy` convention from `main_test.go`.

## Documentation

- **New file `docs/testing.md`**: line syntax, tool table, rationale for why
  `apply_patch` is excluded, fail-fast behavior, `--policy`/`--host`, an
  example transcript, exit codes, limitation (no `cwd`/`session_id`/
  `permission_mode` controllable — `when:` rules that access those can't be
  reproduced exactly in test mode).
- **`README.md`**: new row in the existing invocation-forms table
  (`hookguard test <file>`), pointer to `docs/testing.md`.
- **`docs/getting-started.md`**: short pointer paragraph under "Quick smoke
  test", referencing `docs/testing.md` instead of duplicating it.
- **`CONTEXT.md`**: two new glossary entries in the existing style ("Test
  file", "Test case"), linked to **Action** (not "Result" — the codebase
  consistently uses "Action") and **Host** (since `--host` picks the
  simulated host).
- No ADR: additive, not hard to reverse, no real architectural surprise —
  the two design decisions (fail-fast, reusing `decide()`) are instead
  captured briefly as a design note in `docs/testing.md`.

## Implementation order

1. `cmd/hookguard/testmode.go` (types/functions).
2. `cmd/hookguard/main.go`: doc comment + dispatch in `main()`.
3. `cmd/hookguard/testmode_test.go` (unit + integration tests).
4. `go build ./...` and `go test ./...` — make sure nothing breaks.
5. New `docs/testing.md`; `README.md` and `getting-started.md` pointers.
6. `CONTEXT.md` glossary entries.

## Verification

- `go test ./...` green, especially the new `testmode_test.go` cases.
- Manual smoke test:
  ```bash
  cat > /tmp/policy-tests.txt <<'EOF'
  Bash: git commit -m "Test Commit" --no-verify -> deny
  Bash: git -n commit -m "Test" -> deny
  Bash: ls -la -> allow
  EOF
  ./hookguard test /tmp/policy-tests.txt --policy config/hookguard.yaml
  echo "exit: $?"
  ```
  Expected: 3/3 passed, exit 0. Then introduce a line with a wrong expected
  decision and check that FAIL + reason appear and exit is 1.
- Test `--host codex` against an `ask` rule and check that it shows as
  `deny` (the downgrade also applies in test mode).

## Critical files

- `cmd/hookguard/main.go` (dispatch change, reused functions: `decide`,
  `resolvePolicyPath`, `host` type)
- `cmd/hookguard/testmode.go` (new)
- `cmd/hookguard/testmode_test.go` (new)
- `cmd/hookguard/main_test.go` (reference for test conventions)
- `internal/policy/policy.go` (`Action` constants, `Load`)
- `docs/testing.md` (new)
- `README.md`, `docs/getting-started.md`, `CONTEXT.md`
