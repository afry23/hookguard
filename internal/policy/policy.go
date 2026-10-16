// Package policy loads a YAML hookguard configuration and evaluates tool
// calls against a CEL-based rules list, returning allow / deny / ask
// decisions.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"

	"github.com/afry23/hookguard/internal/powershell"
	"github.com/afry23/hookguard/internal/shell"
)

// ─── action type ─────────────────────────────────────────────────────────────

// Action is the outcome of a policy evaluation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAsk   Action = "ask"
)

// Severity returns a numeric rank for an action so we can pick the most
// restrictive outcome across multiple matching rules (or segments).
//
//	deny(2) > ask(1) > allow(0)
func Severity(a Action) int {
	switch a {
	case ActionDeny:
		return 2
	case ActionAsk:
		return 1
	case ActionAllow:
		return 0
	default:
		return -1
	}
}

// ─── YAML schema ─────────────────────────────────────────────────────────────

// Rule is a single entry in the policy's rules list. It matches a tool call
// via sugar fields, a raw when-expression, or both (ANDed together), and
// resolves to Action if it matches.
type Rule struct {
	// Bash sugar (exclusive with Tools/Path/Cmdlet).
	Tool       string   `yaml:"tool"`
	Subcommand string   `yaml:"subcommand"`
	DenyFlags  []string `yaml:"deny_flags"`

	// PowerShell sugar (exclusive with Tool/Tools/Path). DenyFlags is shared
	// with the Bash sugar above: for a Cmdlet rule it checks both PSSegment
	// parameter names and switch names (value not compared -- see ADR 0005).
	Cmdlet string `yaml:"cmdlet"`

	// Path sugar (Read/Edit/Write).
	Tools []string `yaml:"tools"`
	Path  string   `yaml:"path"`

	// Raw CEL, ANDed with any sugar expression present.
	When string `yaml:"when"`

	Action Action `yaml:"action"`
	Reason string `yaml:"reason"`

	// set by Load(), not from YAML.
	program    cel.Program
	scopeTools map[string]bool // nil = evaluate for every tool_name
}

// Policy is the root configuration object loaded from hookguard.yaml.
type Policy struct {
	Version  int    `yaml:"version"`
	AuditLog string `yaml:"audit_log"`

	// DefaultAction is the fallback when no rule matches a tool call.
	// Defaults to "deny" (secure default) when empty.
	DefaultAction Action `yaml:"default_action"`

	// Rules is the unified list of rules evaluated for every tool call.
	Rules []Rule `yaml:"rules"`

	// OpaqueGuard controls the decision when a Bash command contains a
	// construct that cannot be safely decomposed into segments.
	// Defaults to "ask" when empty.
	OpaqueGuard OpaqueGuard `yaml:"opaque_execution_guard"`

	// PowerShellOpaqueGuard controls the decision when a PowerShell command
	// cannot be safely parsed, or contains a construct that cannot be safely
	// decomposed into PowerShell-Segments (Invoke-Expression, dot-sourcing,
	// dynamic call-operator targets, -EncodedCommand, Add-Type, control
	// structures, etc). Configured separately from OpaqueGuard (Bash) since
	// the two parsers are independent implementations with independent risk
	// profiles -- see docs/adr/0005-hand-written-powershell-tokenizer.md.
	// Defaults to "ask" when empty.
	PowerShellOpaqueGuard OpaqueGuard `yaml:"powershell_opaque_execution_guard"`

	// PatchOpaqueGuard controls the decision when a Codex apply_patch call's
	// raw patch text cannot be safely decomposed into Patch-Segments.
	// Defaults to "ask" when empty.
	PatchOpaqueGuard OpaqueGuard `yaml:"patch_opaque_execution_guard"`
}

// OpaqueGuard controls what happens when an opaque execution construct is
// detected (eval, sh -c, command substitution, etc.).
type OpaqueGuard struct {
	Action Action `yaml:"action"`
}

// ─── Activation / EvalResult ─────────────────────────────────────────────────

// Activation carries the variables available to rule evaluation for exactly
// one tool call (or one Bash/PowerShell/Patch segment within a tool call).
type Activation struct {
	ToolName  string
	ToolInput map[string]any
	Cwd       string
	SessionID string
	Segment   *shell.Segment      // nil for non-Bash tool calls
	PSSegment *powershell.Segment // nil for non-PowerShell tool calls

	// Codex-only fields; empty string for Claude Code invocations.
	// Only usable via raw when: expressions — not exposed through sugar fields.
	Model          string
	PermissionMode string
	TurnID         string
	ToolUseID      string
	TranscriptPath string
}

// EvalResult is the outcome of evaluating one Activation.
type EvalResult struct {
	Action Action
	Reason string // human-readable reason, fed back to Claude on deny/ask
}

// ─── Load ────────────────────────────────────────────────────────────────────

// Load reads and validates a policy from a YAML file at path.
// A leading "~/" in path is expanded to the user's home directory.
func Load(path string) (*Policy, error) {
	path = expandHome(path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy %q: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	// Secure defaults.
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	if p.OpaqueGuard.Action == "" {
		p.OpaqueGuard.Action = ActionAsk
	}
	if p.PowerShellOpaqueGuard.Action == "" {
		p.PowerShellOpaqueGuard.Action = ActionAsk
	}
	if p.PatchOpaqueGuard.Action == "" {
		p.PatchOpaqueGuard.Action = ActionAsk
	}

	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}

	for i := range p.Rules {
		if err := compileRule(&p.Rules[i], env); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
	}

	return &p, nil
}

// ─── Evaluate ────────────────────────────────────────────────────────────────

// Evaluate applies every rule to a single Activation and returns the most
// severe matching decision (deny > ask > allow), or the policy's
// DefaultAction if no rule matches.
func (p *Policy) Evaluate(a Activation) EvalResult {
	best := EvalResult{}
	bestSeverity := -1

	segMap := segmentToMap(a.Segment)
	psSegMap := psSegmentToMap(a.PSSegment)

	for i := range p.Rules {
		r := &p.Rules[i]

		if r.scopeTools != nil && !r.scopeTools[a.ToolName] {
			continue
		}

		vars := map[string]any{
			"tool_name":       a.ToolName,
			"tool_input":      toolInputToMap(a.ToolInput),
			"segment":         segMap,
			"ps_segment":      psSegMap,
			"cwd":             a.Cwd,
			"session_id":      a.SessionID,
			"model":           a.Model,
			"permission_mode": a.PermissionMode,
			"turn_id":         a.TurnID,
			"tool_use_id":     a.ToolUseID,
			"transcript_path": a.TranscriptPath,
		}

		out, _, err := r.program.Eval(vars)
		if err != nil {
			// Runtime error: this rule counts as matched with action "ask" so
			// it participates in severity resolution instead of being
			// silently dropped (a deny elsewhere still wins).
			if Severity(ActionAsk) > bestSeverity {
				best = EvalResult{
					Action: ActionAsk,
					Reason: fmt.Sprintf("rule %d: CEL evaluation error: %v", i, err),
				}
				bestSeverity = Severity(ActionAsk)
			}
			continue
		}

		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		sev := Severity(r.Action)
		if sev > bestSeverity {
			reason := r.Reason
			if reason == "" {
				reason = fmt.Sprintf("rule %d matched (action=%s)", i, r.Action)
			}
			best = EvalResult{Action: r.Action, Reason: reason}
			bestSeverity = sev
		}
	}

	if bestSeverity == -1 {
		return EvalResult{
			Action: p.DefaultAction,
			Reason: fmt.Sprintf("no rule matched (default_action=%s)", p.DefaultAction),
		}
	}

	return best
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func toolInputToMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func segmentToMap(s *shell.Segment) map[string]any {
	if s == nil {
		return map[string]any{
			"tool":       "",
			"subcommand": "",
			"flags":      []string{},
			"args":       []string{},
		}
	}
	return map[string]any{
		"tool":       s.Tool,
		"subcommand": s.Subcommand,
		"flags":      toAnySlice(s.Flags),
		"args":       toAnySlice(s.Args),
	}
}

func psSegmentToMap(s *powershell.Segment) map[string]any {
	if s == nil {
		return map[string]any{
			"cmdlet":     "",
			"parameters": map[string]any{},
			"switches":   []any{},
			"args":       []any{},
		}
	}
	params := make(map[string]any, len(s.Parameters))
	for k, v := range s.Parameters {
		params[k] = v
	}
	return map[string]any{
		"cmdlet":     s.Cmdlet,
		"parameters": params,
		"switches":   toAnySlice(s.Switches),
		"args":       toAnySlice(s.Args),
	}
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
