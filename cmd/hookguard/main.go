// hookguard is a PreToolUse hook for Claude Code and Codex CLI that enforces
// a YAML security policy against tool calls (Bash, PowerShell, apply_patch,
// Read, Edit, Write, …) before the agent executes them.
//
// The agent CLI sends a JSON object via stdin; hookguard returns a JSON object
// on stdout with a permissionDecision of "allow", "deny", or "ask".
//
// Usage:
//
//	hookguard              # Claude Code (default)
//	hookguard claude       # Claude Code (explicit)
//	hookguard codex        # Codex CLI
//	hookguard test <file>  # run a testfile of Tool: Value -> decision cases
//
// The binary is designed to be invoked once per tool call.  Start-up time is
// in the low single-digit milliseconds (no interpreter, no runtime warm-up).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/afry23/hookguard/internal/audit"
	"github.com/afry23/hookguard/internal/patch"
	"github.com/afry23/hookguard/internal/policy"
	"github.com/afry23/hookguard/internal/powershell"
	"github.com/afry23/hookguard/internal/shell"
)

// goos is indirected through a package var so tests can simulate Windows on
// any CI OS without build tags.
var goos = runtime.GOOS

// ─── host type ───────────────────────────────────────────────────────────────

type host string

const (
	hostClaude host = "claude"
	hostCodex  host = "codex"
)

// parseHost reads os.Args[1]; "codex" → hostCodex, anything else (no args,
// "claude", or an unrecognized value) → hostClaude, preserving backward
// compatibility with bare `hookguard` invocations.
func parseHost(args []string) host {
	if len(args) >= 2 && args[1] == "codex" {
		return hostCodex
	}
	return hostClaude
}

// ─── Claude Code / Codex hook wire types ─────────────────────────────────────

// hookInput is the JSON object an agent CLI sends to a PreToolUse hook on stdin.
// Codex-only fields decode as zero-values under Claude Code input.
type hookInput struct {
	SessionID string         `json:"session_id"`
	Cwd       string         `json:"cwd"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`

	// Codex-only fields (absent / zero-value in Claude Code payloads).
	TurnID         string  `json:"turn_id"`
	ToolUseID      string  `json:"tool_use_id"`
	PermissionMode string  `json:"permission_mode"`
	Model          string  `json:"model"`
	TranscriptPath *string `json:"transcript_path"` // nullable per Codex spec
}

// hookOutput is the JSON object we write to stdout.
// Exit code must be 0 when using JSON output; exit 2 causes Claude Code to
// ignore the JSON body and use stderr as the block reason instead.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// ─── main ────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "test" {
		os.Exit(runTestMode(os.Args[2:], os.Stdout, os.Stderr))
	}
	runHook(parseHost(os.Args))
}

func runHook(h host) {
	var input hookInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		respond("ask", fmt.Sprintf("hookguard: stdin decode error: %v", err))
		return
	}

	policyPath := resolvePolicyPath(h)
	pol, err := policy.Load(policyPath)
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

	action, reason := decide(input, pol, h)

	if pol.AuditLog != "" {
		entry := audit.Entry{
			Host:      string(h),
			SessionID: input.SessionID,
			Cwd:       input.Cwd,
			ToolName:  input.ToolName,
			Action:    string(action),
			Reason:    reason,
		}
		if input.ToolName == "Bash" || input.ToolName == "PowerShell" || input.ToolName == "apply_patch" {
			entry.Command, _ = input.ToolInput["command"].(string)
		} else if pol.AuditToolInput {
			entry.ToolInput = audit.TruncateInput(input.ToolInput)
		}
		_ = audit.Write(pol.AuditLog, entry)
	}

	respond(string(action), reason)
}

// ─── decision logic ──────────────────────────────────────────────────────────

// decide wraps decideRaw and applies the ask→deny downgrade for Codex hosts,
// which have no interactive ask channel.
func decide(input hookInput, pol *policy.Policy, h host) (policy.Action, string) {
	action, reason := decideRaw(input, pol, h)
	if h == hostCodex && action == policy.ActionAsk {
		return policy.ActionDeny, "ask downgraded to deny (Codex has no ask channel): " + reason
	}
	return action, reason
}

// decideRaw dispatches on tool_name and returns the raw policy decision before
// any host-specific post-processing.
func decideRaw(input hookInput, pol *policy.Policy, h host) (policy.Action, string) {
	switch input.ToolName {
	case "PowerShell":
		return decidePowerShellCommand(input, pol)
	case "apply_patch":
		return decideApplyPatch(input, pol)
	case "Bash":
		// Codex reports all Windows shell execution as "Bash"; route to the
		// PowerShell path so cmdlet: rules apply correctly.
		if h == hostCodex && goos == "windows" {
			return decidePowerShellCommand(input, pol)
		}
		return decideBashCommand(input, pol)
	default:
		result := pol.Evaluate(policy.Activation{
			ToolName:       input.ToolName,
			ToolInput:      input.ToolInput,
			Cwd:            input.Cwd,
			SessionID:      input.SessionID,
			Model:          input.Model,
			PermissionMode: input.PermissionMode,
			TurnID:         input.TurnID,
			ToolUseID:      input.ToolUseID,
			TranscriptPath: derefString(input.TranscriptPath),
		})
		return result.Action, result.Reason
	}
}

func decideBashCommand(input hookInput, pol *policy.Policy) (policy.Action, string) {
	cmdStr, _ := input.ToolInput["command"].(string)
	parseResult, _ := shell.Parse(cmdStr)

	switch {
	case parseResult.HasOpaqueExec:
		return pol.OpaqueGuard.Action, "opaque execution detected: " + parseResult.OpaqueReason
	case len(parseResult.Segments) == 0:
		return policy.ActionAllow, ""
	default:
		acts := make([]policy.Activation, len(parseResult.Segments))
		for i := range parseResult.Segments {
			seg := parseResult.Segments[i]
			acts[i] = policy.Activation{
				ToolName:  input.ToolName,
				ToolInput: input.ToolInput,
				Cwd:       input.Cwd,
				SessionID: input.SessionID,
				Segment:   &seg,
			}
		}
		return evaluateMostSevere(pol, acts)
	}
}

func decidePowerShellCommand(input hookInput, pol *policy.Policy) (policy.Action, string) {
	cmdStr, _ := input.ToolInput["command"].(string)
	parseResult, _ := powershell.Parse(cmdStr)

	switch {
	case parseResult.HasOpaqueExec:
		return pol.PowerShellOpaqueGuard.Action, "PowerShell opaque execution detected: " + parseResult.OpaqueReason
	case len(parseResult.Segments) == 0:
		return policy.ActionAllow, ""
	default:
		acts := make([]policy.Activation, len(parseResult.Segments))
		for i := range parseResult.Segments {
			seg := parseResult.Segments[i]
			acts[i] = policy.Activation{
				ToolName:  "PowerShell", // always evaluate against PowerShell rules
				ToolInput: input.ToolInput,
				Cwd:       input.Cwd,
				SessionID: input.SessionID,
				PSSegment: &seg,
			}
		}
		return evaluateMostSevere(pol, acts)
	}
}

func decideApplyPatch(input hookInput, pol *policy.Policy) (policy.Action, string) {
	cmdStr, _ := input.ToolInput["command"].(string)
	parseResult, _ := patch.Parse(cmdStr)

	switch {
	case parseResult.HasOpaqueExec:
		return pol.PatchOpaqueGuard.Action, "apply_patch opaque: " + parseResult.OpaqueReason
	case len(parseResult.Segments) == 0:
		return policy.ActionAllow, ""
	default:
		acts := make([]policy.Activation, len(parseResult.Segments))
		for i, seg := range parseResult.Segments {
			acts[i] = policy.Activation{
				ToolName:       seg.EffectiveTool,
				ToolInput:      map[string]any{"file_path": seg.Path},
				Cwd:            input.Cwd,
				SessionID:      input.SessionID,
				Model:          input.Model,
				PermissionMode: input.PermissionMode,
				TurnID:         input.TurnID,
				ToolUseID:      input.ToolUseID,
				TranscriptPath: derefString(input.TranscriptPath),
			}
		}
		return evaluateMostSevere(pol, acts)
	}
}

// evaluateMostSevere evaluates each Activation and returns the most severe
// result (deny > ask > allow). Returns allow with empty reason if acts is empty.
func evaluateMostSevere(pol *policy.Policy, acts []policy.Activation) (policy.Action, string) {
	action := policy.ActionAllow
	reason := ""
	for _, a := range acts {
		result := pol.Evaluate(a)
		if policy.Severity(result.Action) > policy.Severity(action) {
			action = result.Action
			reason = result.Reason
		}
	}
	return action, reason
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// respond writes the hook output JSON to stdout and exits 0.
// Exit 0 is required when the body is a structured JSON decision; exit 2
// would cause Claude Code to treat the whole output as a block reason string.
func respond(decision, reason string) {
	out := hookOutput{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	os.Exit(0)
}

// resolvePolicyPath returns the path to hookguard.yaml, checked in order:
//  1. $HOOKGUARD_POLICY environment variable
//  2. ~/.claude/hookguard.yaml for Claude Code, ~/.codex/hookguard.yaml for Codex
func resolvePolicyPath(h host) string {
	if p := os.Getenv("HOOKGUARD_POLICY"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "hookguard.yaml"
	}
	dir := ".claude"
	if h == hostCodex {
		dir = ".codex"
	}
	return filepath.Join(home, dir, "hookguard.yaml")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
