// hookguard is a Claude Code PreToolUse hook that enforces a YAML security
// policy against Bash commands and other tool calls (Read, Edit, Write, …)
// before Claude Code executes them.
//
// Claude Code sends a JSON object via stdin; hookguard returns a JSON object
// on stdout with a permissionDecision of "allow", "deny", or "ask".
//
// Usage:
//
//	HOOKGUARD_POLICY=/path/to/hookguard.yaml hookguard
//
// The binary is designed to be invoked once per tool call.  Start-up time is
// in the low single-digit milliseconds (no interpreter, no runtime warm-up).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"hookguard/internal/audit"
	"hookguard/internal/policy"
	"hookguard/internal/powershell"
	"hookguard/internal/shell"
)

// ─── Claude Code hook wire types ─────────────────────────────────────────────

// hookInput is the JSON object Claude Code sends to a PreToolUse hook on stdin.
// Only fields relevant to our policy check are decoded; the rest are ignored.
type hookInput struct {
	SessionID string         `json:"session_id"`
	Cwd       string         `json:"cwd"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
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
	// 1. Decode the hook payload from stdin.
	var input hookInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		// If we cannot parse the input we cannot make a sound policy decision.
		respond("ask", fmt.Sprintf("hookguard: stdin decode error: %v", err))
		return
	}

	// 2. Load the policy file.
	policyPath := resolvePolicyPath()
	pol, err := policy.Load(policyPath)
	if err != nil {
		// When the policy file is unavailable, default to "ask" so the user is
		// not silently blocked (deny) nor silently allowed (allow).
		// Override with HOOKGUARD_FAIL_MODE=deny for stricter CI environments.
		failMode := envOrDefault("HOOKGUARD_FAIL_MODE", "ask")
		respond(failMode, fmt.Sprintf("hookguard: policy unavailable (%s): %v", policyPath, err))
		return
	}

	// 3. Decide.
	action, reason := decide(input, pol)

	// 4. Write audit log entry (best-effort; errors are silently ignored so
	//    a broken audit path never blocks a legitimate operation).
	if pol.AuditLog != "" {
		entry := audit.Entry{
			SessionID: input.SessionID,
			Cwd:       input.Cwd,
			ToolName:  input.ToolName,
			Action:    string(action),
			Reason:    reason,
		}
		if input.ToolName == "Bash" || input.ToolName == "PowerShell" {
			entry.Command, _ = input.ToolInput["command"].(string)
		}
		_ = audit.Write(pol.AuditLog, entry)
	}

	// 5. Respond to Claude Code.
	respond(string(action), reason)
}

// decide encapsulates the full policy decision logic for a single hook
// invocation, independent of stdin/stdout, so it can be unit-tested directly.
func decide(input hookInput, pol *policy.Policy) (policy.Action, string) {
	if input.ToolName == "PowerShell" {
		cmdStr, _ := input.ToolInput["command"].(string)
		parseResult, _ := powershell.Parse(cmdStr)

		switch {
		case parseResult.HasOpaqueExec:
			return pol.PowerShellOpaqueGuard.Action, "PowerShell opaque execution detected: " + parseResult.OpaqueReason

		case len(parseResult.Segments) == 0:
			return policy.ActionAllow, ""

		default:
			action := policy.ActionAllow
			reason := ""
			for _, seg := range parseResult.Segments {
				seg := seg
				result := pol.Evaluate(policy.Activation{
					ToolName:  input.ToolName,
					ToolInput: input.ToolInput,
					Cwd:       input.Cwd,
					SessionID: input.SessionID,
					PSSegment: &seg,
				})
				if policy.Severity(result.Action) > policy.Severity(action) {
					action = result.Action
					reason = result.Reason
				}
			}
			return action, reason
		}
	}

	if input.ToolName != "Bash" {
		result := pol.Evaluate(policy.Activation{
			ToolName:  input.ToolName,
			ToolInput: input.ToolInput,
			Cwd:       input.Cwd,
			SessionID: input.SessionID,
		})
		return result.Action, result.Reason
	}

	cmdStr, _ := input.ToolInput["command"].(string)
	parseResult, _ := shell.Parse(cmdStr)

	switch {
	case parseResult.HasOpaqueExec:
		return pol.OpaqueGuard.Action, "opaque execution detected: " + parseResult.OpaqueReason

	case len(parseResult.Segments) == 0:
		// Empty or comment-only command — nothing to block.
		return policy.ActionAllow, ""

	default:
		// Evaluate every segment in the command (pipeline, &&, ;, …).
		// The most restrictive outcome across all segments wins:
		//   deny > ask > allow
		action := policy.ActionAllow
		reason := ""
		for _, seg := range parseResult.Segments {
			seg := seg
			result := pol.Evaluate(policy.Activation{
				ToolName:  input.ToolName,
				ToolInput: input.ToolInput,
				Cwd:       input.Cwd,
				SessionID: input.SessionID,
				Segment:   &seg,
			})
			if policy.Severity(result.Action) > policy.Severity(action) {
				action = result.Action
				reason = result.Reason
			}
		}
		return action, reason
	}
}

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
//  2. ~/.claude/hookguard.yaml  (user-level, single developer)
func resolvePolicyPath() string {
	if p := os.Getenv("HOOKGUARD_POLICY"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "hookguard.yaml"
	}
	return filepath.Join(home, ".claude", "hookguard.yaml")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
