# Codex CLI hook support for hookguard

## Context

`hookguard` today is a Claude Code `PreToolUse` hook only: a single binary that
reads a Claude Code hook JSON payload on stdin, evaluates it against a CEL
policy, and writes back an allow/deny/ask decision. The user wants to also
protect OpenAI Codex CLI sessions with the same policy engine, so one
`hookguard.yaml` can guard both agent CLIs.

A design-interview session (grill-with-docs) already resolved every
architectural question this raises — recorded in `CONTEXT.md` (new terms:
**Host**, **Ask-to-deny downgrade**, **Patch-Segment**, **Patch opaque
guard**) and `docs/adr/0006-0008`. This plan turns those decisions into
concrete code changes; it does not revisit them. One additional edge case
surfaced during planning (missing-policy-file fail path) was clarified with
the user and is folded in below.

Key facts about Codex's hook protocol (confirmed against Codex's official
docs at developers.openai.com/codex/hooks) that drive this plan:
- Same `hookSpecificOutput.permissionDecision` JSON shape as Claude Code, but
  **no `ask`** support (parsed, not honored) — hence the downgrade.
- File edits arrive as a single `apply_patch` call whose `tool_input.command`
  is raw patch text (`*** Begin Patch` / `*** Add File:` / `*** Update File:`
  / `*** Delete File:` / `*** Move to:` / `*** End Patch`), not per-file
  `Edit`/`Write` calls.
- All shell execution — even PowerShell on Windows — is reported as
  `tool_name: "Bash"`; there is no separate `PowerShell` tool_name in Codex.
- Extra stdin fields Claude Code never sends: `turn_id`, `tool_use_id`,
  `permission_mode`, `model`, `transcript_path`.

## Implementation order

1. `internal/patch` (new package, no dependents — parse in isolation first)
2. `internal/policy` changes (new guard field, new CEL vars/Activation fields)
3. `internal/audit` (`Host` field)
4. `cmd/hookguard/main.go` restructuring (subcommand dispatch, decide(), etc.)
5. Tests alongside each step above
6. `README.md` and `config/hookguard.yaml` documentation updates

## 1. New package `internal/patch`

`internal/patch/parser.go`, mirroring the shape of `internal/shell/tokenizer.go`
and `internal/powershell/parser.go`:

```go
package patch

type Op string

const (
	OpAdd        Op = "add"         // *** Add File          -> EffectiveTool "Write"
	OpUpdate     Op = "update"      // *** Update File        -> "Edit"
	OpDelete     Op = "delete"      // *** Delete File        -> "Edit"
	OpMoveSource Op = "move_source" // source side of Move to -> "Edit"
	OpMoveDest   Op = "move_dest"   // dest side of Move to   -> "Write"
)

// Segment is one parsed file operation (Patch-Segment, see CONTEXT.md)
// extracted from an apply_patch call's raw patch text.
type Segment struct {
	Op            Op
	Path          string
	EffectiveTool string // "Edit" or "Write" -- what to evaluate this against
}

type ParseResult struct {
	Segments      []Segment
	HasOpaqueExec bool // could not be safely decomposed into Patch-Segments
	OpaqueReason  string
}

func Parse(text string) (*ParseResult, error)
```

`Parse()` is a line-oriented scan (tolerate `\r\n`):
- Requires a `*** Begin Patch` / `*** End Patch` envelope; missing either →
  opaque (`"missing *** Begin Patch/*** End Patch envelope"`).
- Recognizes section headers `*** Add File: <path>`, `*** Delete File: <path>`,
  `*** Update File: <path>` (optionally followed by `*** Move to: <path>`),
  skipping `@@` hunks and `+`/`-`/context lines in between — only op + path
  matter for policy matching, hunk content is irrelevant and not modeled.
- `Delete File` → `Segment{OpDelete, path, "Edit"}` immediately (per the
  **Patch-Segment** glossary entry: Delete evaluates as Edit).
- `Update File` with a following `Move to` → two Segments: source path as
  `OpMoveSource`/"Edit", destination path as `OpMoveDest`/"Write". Without
  `Move to` → single `OpUpdate`/"Edit" Segment.
- Any other `***`-prefixed line that isn't a recognized header, or an empty
  path after a header's `: `, or content before the first section header →
  opaque (specific reason string per case).
- Empty/whitespace-only input → `ParseResult{}`, not opaque (mirrors
  `shell.Parse`'s handling of empty commands).
- The same path appearing in two sections of one patch is allowed — each
  becomes its own independent Segment, no cross-section dedup.

Reuse the `HasOpaqueExec`/`OpaqueReason` field names (matching the other two
parser packages) even though "opaque execution" is a slight misnomer for a
parse failure — keeps `main.go`'s three dispatch branches symmetric.

### Tests: `internal/patch/parser_test.go`
Single Add / Update / Delete; Update+Move (two segments); multiple sections
in one patch, order preserved; missing Begin/End Patch; unrecognized header;
empty path; empty input (not opaque); hunk bodies and `*** End of File`
correctly skipped; CRLF tolerance.

## 2. `internal/policy` changes

**No new CEL variable for patch segments.** Per the apply_patch-normalization
decision, `main.go` evaluates each Patch-Segment via the *existing*
`tools`/`path` sugar path — `pol.Evaluate(Activation{ToolName: seg.EffectiveTool,
ToolInput: map[string]any{"file_path": seg.Path}, ...})` — so `sugar.go` and
`scopeToolsFor` need zero changes.

**`internal/policy/policy.go`** — add to `Policy` struct, mirroring
`OpaqueGuard`/`PowerShellOpaqueGuard` exactly:
```go
	// PatchOpaqueGuard controls the decision when a Codex apply_patch call's
	// raw patch text cannot be safely decomposed into Patch-Segments.
	// Defaults to "ask" when empty.
	PatchOpaqueGuard OpaqueGuard `yaml:"patch_opaque_execution_guard"`
```
and in `Load()`, alongside the two existing default-fill lines:
```go
	if p.PatchOpaqueGuard.Action == "" {
		p.PatchOpaqueGuard.Action = ActionAsk
	}
```

Add Codex-only fields to `Activation` (empty string under Claude Code, not
exposed via any sugar field — only usable from raw `when:` expressions):
```go
	Model          string
	PermissionMode string
	TurnID         string
	ToolUseID      string
	TranscriptPath string
```
Wire them into `Evaluate()`'s `vars` map (`"model"`, `"permission_mode"`,
`"turn_id"`, `"tool_use_id"`, `"transcript_path"`).

**`internal/policy/cel_env.go`** — add matching `cel.Variable(..., cel.StringType)`
declarations for the same five names in `newCELEnv()`.

### Tests
Policy-load test: `patch_opaque_execution_guard: { action: deny }` sets
`PatchOpaqueGuard.Action`; omitted key defaults to `ask`. A `when:` test
exercising one Codex-only var (e.g. `permission_mode == "auto"`) and a test
confirming these vars default to `""` with no CEL runtime error when unused.

## 3. `internal/audit` changes

`internal/audit/audit.go`, `Entry` struct — add after `SessionID`:
```go
	// Host is which agent CLI invoked hookguard for this call: "claude" or
	// "codex".
	Host string `json:"host,omitempty"`
```
Update the `Command` field's doc comment to note it's also set for
`apply_patch` calls now. No `Write()` changes. Add a round-trip test
asserting `Host` marshals and is omitted when empty.

## 4. `cmd/hookguard/main.go` restructuring

### Host type + subcommand dispatch (host is NEVER sniffed from stdin)
```go
type host string

const (
	hostClaude host = "claude"
	hostCodex  host = "codex"
)

func main() {
	runHook(parseHost(os.Args))
}

// parseHost reads os.Args[1]; "codex" -> hostCodex, anything else
// (no args, "claude", or an unrecognized value) -> hostClaude, preserving
// today's bare `hookguard` invocation for backward compatibility.
func parseHost(args []string) host {
	if len(args) >= 2 && args[1] == "codex" {
		return hostCodex
	}
	return hostClaude
}
```

### `resolvePolicyPath(h host) string`
Same as today but the home-relative fallback directory is `.claude` for
`hostClaude` and `.codex` for `hostCodex` (ADR 0008); `HOOKGUARD_POLICY`
still overrides either.

### Shared severity-reduction helper
Extract the "evaluate N activations, keep the highest-severity result"
pattern (today duplicated for Bash and PowerShell) into one helper used a
third time for Patch-Segments:
```go
func evaluateMostSevere(pol *policy.Policy, acts []policy.Activation) (policy.Action, string) {
	action := policy.ActionAllow
	reason := ""
	for _, a := range acts {
		result := pol.Evaluate(a)
		if policy.Severity(result.Action) > policy.Severity(action) {
			action, reason = result.Action, result.Reason
		}
	}
	return action, reason
}
```

### `decide()` gains a `host` parameter; downgrade applied once, centrally
```go
func decide(input hookInput, pol *policy.Policy, h host) (policy.Action, string) {
	action, reason := decideRaw(input, pol, h)
	if h == hostCodex && action == policy.ActionAsk {
		return policy.ActionDeny, "ask downgraded to deny (Codex has no ask channel): " + reason
	}
	return action, reason
}
```
`decideRaw` dispatches on `input.ToolName`:
- `"PowerShell"` → existing per-Segment loop (now built as `[]policy.Activation`
  fed to `evaluateMostSevere`).
- `"apply_patch"` → new `decideApplyPatch(input, pol, h)`: parse via
  `patch.Parse`, opaque → `pol.PatchOpaqueGuard.Action`, empty → allow,
  else build one `Activation{ToolName: seg.EffectiveTool, ToolInput:
  {"file_path": seg.Path}, ...}` per Patch-Segment and reduce via
  `evaluateMostSevere`.
- `"Bash"` → if `h == hostCodex && goos == "windows"`, dispatch to the same
  PowerShell-handling path as the `"PowerShell"` case (Codex reports all
  Windows shell execution as `"Bash"`); otherwise today's Bash path.
- default → today's single `pol.Evaluate()` call, now also threading the
  five Codex-only fields from `input` into the `Activation`.

Extract today's inlined Bash-handling and PowerShell-handling blocks into
named helpers (`decideBashCommand`, `decidePowerShellCommand`) so the
Windows-Bash-under-Codex branch can call `decidePowerShellCommand` directly
instead of duplicating it.

`goos` is indirected through a package var (`var goos = runtime.GOOS`) so
tests can simulate Windows on any CI OS without build tags.

### `hookInput` gains the Codex fields
```go
	TurnID         string  `json:"turn_id"`
	ToolUseID      string  `json:"tool_use_id"`
	PermissionMode string  `json:"permission_mode"`
	Model          string  `json:"model"`
	TranscriptPath *string `json:"transcript_path"` // nullable per Codex spec
```
These simply decode as zero-values under Claude Code input — no per-host
branching needed at decode time.

### `runHook(h host)` (today's `main()` body)
- Loads policy via `resolvePolicyPath(h)`.
- **Missing/unreadable policy file** (clarified with user during planning):
  apply the same ask→deny downgrade here too, since this path responds
  before `decide()` ever runs:
  ```go
  if err != nil {
  	failMode := envOrDefault("HOOKGUARD_FAIL_MODE", "ask")
  	if h == hostCodex && failMode == "ask" {
  		respond("deny", fmt.Sprintf(
  			"hookguard: policy unavailable (%s): %v (ask downgraded to deny under Codex)",
  			policyPath, err))
  		return
  	}
  	respond(failMode, fmt.Sprintf("hookguard: policy unavailable (%s): %v", policyPath, err))
  	return
  }
  ```
- Calls `decide(input, pol, h)`.
- Audit entry gains `Host: string(h)`, and the `Command`-population condition
  extends to `input.ToolName == "apply_patch"` alongside `Bash`/`PowerShell`.

New imports: `"runtime"`, `"hookguard/internal/patch"`.

### Tests: `cmd/hookguard/main_test.go`
Update all existing `decide(input, pol)` calls to `decide(input, pol, hostClaude)`.
Add:
- Codex ask→deny downgrade (including on a non-Bash/path rule, to confirm
  decision 1's "applies for every tool_name" scope).
- Claude host unaffected by the same `ask`-resolving rule.
- `apply_patch`: Add File, Delete-as-Edit, Move (split source/dest), and a
  multi-file patch where one file matches deny and one doesn't → overall
  deny.
- `apply_patch` opaque guard on malformed patch text.
- `goos = "windows"` + hostCodex + `ToolName: "Bash"` + PowerShell-flavored
  command → matches a `cmdlet:` rule (same as native `"PowerShell"` input).
- `goos = "linux"` + hostCodex + `ToolName: "Bash"` → still matches Bash
  `tool:`/`subcommand:` rules.
- `hostClaude` + `goos = "windows"` → Bash path unaffected (guards against
  accidentally widening the branch to Claude).
- `parseHost` table test (`nil args`/`"claude"`/`"codex"`/unrecognized value).
- `resolvePolicyPath` per-host default path test, and `HOOKGUARD_POLICY`
  override test (`t.Setenv`).
- Missing-policy-file + `hostCodex` + default fail mode → responds `deny`,
  not `ask`.

## 5. `README.md` updates
- Mention both Claude Code and Codex CLI as supported hosts up top.
- New "Register as a Codex CLI hook" section with a `~/.codex/config.toml`
  snippet (`command = "hookguard codex"`, matchers for `Bash`/`apply_patch`),
  noting there's no separate PowerShell matcher under Codex.
- Note per-host default policy path (`~/.claude/hookguard.yaml` vs
  `~/.codex/hookguard.yaml`), referencing ADR 0008.
- Document `patch_opaque_execution_guard` alongside the two existing guard
  blocks in the schema reference.
- Note the Ask-to-deny downgrade (ADR 0006).
- Add the five Codex-only CEL variables to the CEL variable table.
- Mention the audit log's new `host` field and that `cmd` now also covers
  `apply_patch`.
- Add `internal/patch/` to the project-structure tree.
- Document the three invocation forms: bare `hookguard` (= claude),
  `hookguard claude`, `hookguard codex`.

## 6. `config/hookguard.yaml` example
Add a `patch_opaque_execution_guard: { action: ask }` block next to the two
existing opaque-guard blocks, so the shipped example stays complete.

## Verification
1. `go build ./...` and `go vet ./...` from the repo root.
2. `go test ./...` — all new tests above, plus confirm the existing full
   suite still passes (signature change to `decide()` touches every existing
   test call site).
3. Manual smoke test for each host, from the repo root:
   ```
   echo '{"session_id":"s1","cwd":".","tool_name":"Bash","tool_input":{"command":"git push --force"}}' | ./hookguard claude
   echo '{"session_id":"s1","cwd":".","tool_name":"Bash","tool_input":{"command":"git push --force"}}' | ./hookguard codex
   echo '{"session_id":"s1","cwd":".","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: foo/.env\n+secret\n*** End Patch"}}' | ./hookguard codex
   ```
   confirming: the Codex force-push case denies (not asks, if the matching
   rule is `ask`-rated), and the apply_patch example is caught by an
   existing `path: "**/.env*"` rule without any new policy authored.
4. Confirm `go test ./...` passes on the current OS (Windows) for both the
   `goos == "windows"` and simulated `goos == "linux"` test branches, proving
   the indirection works without needing a second OS runner.
