// Package policy loads a YAML gate configuration and evaluates parsed shell
// segments against it, returning allow / deny / ask decisions.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"ctool-gate/internal/shell"
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
// restrictive outcome across multiple segments in one command.
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

// SubcommandPolicy defines rules for a single subcommand (or the wildcard "*").
type SubcommandPolicy struct {
	// Action is the base decision for this subcommand.
	// Falls back to the parent ToolPolicy.DefaultAction when empty.
	Action Action `yaml:"action"`

	// DenyFlags lists flags that must never appear.
	// Values are matched after flag expansion and alias normalisation, so you
	// only need the canonical long form here (e.g. "--force", not both "-f" and
	// "--force" when a flag_alias mapping exists).
	DenyFlags []string `yaml:"deny_flags"`

	// DenyArgsRegex lists regular expressions matched against positional
	// arguments (not flags).  A match causes a deny decision.
	DenyArgsRegex []string `yaml:"deny_args_regex"`

	// compiled regexes — populated by Load(), not from YAML.
	denyArgsRe []*regexp.Regexp
}

// ToolPolicy defines rules for a top-level CLI tool.
type ToolPolicy struct {
	// DefaultAction is the fallback action when no subcommand policy matches.
	DefaultAction Action `yaml:"default_action"`

	// Subcommands maps subcommand names to their policies.
	// Use "*" as a catch-all for any subcommand not listed explicitly.
	Subcommands map[string]*SubcommandPolicy `yaml:"subcommands"`
}

// OpaqueGuard controls what happens when an opaque execution construct is
// detected (eval, sh -c, command substitution, etc.).
type OpaqueGuard struct {
	Action Action `yaml:"action"`
}

// Policy is the root configuration object loaded from gate.yaml.
type Policy struct {
	Version int    `yaml:"version"`
	AuditLog string `yaml:"audit_log"`

	// DefaultAction is the fallback when a tool is not listed in Tools.
	// Defaults to "deny" (secure default) when empty.
	DefaultAction Action `yaml:"default_action"`

	// FlagAliases maps  tool → subcommand → short_flag → canonical_flag.
	// Applied before deny_flags matching so you can write deny rules using the
	// long form only.
	//
	// Example:
	//   flag_aliases:
	//     git:
	//       push:
	//         "-f": "--force"
	//       commit:
	//         "-n": "--no-verify"
	FlagAliases map[string]map[string]map[string]string `yaml:"flag_aliases"`

	// Tools lists tool-specific policies.
	Tools map[string]*ToolPolicy `yaml:"tools"`

	// OpaqueGuard controls the decision for opaque constructs.
	// Defaults to "ask" when empty.
	OpaqueGuard OpaqueGuard `yaml:"opaque_execution_guard"`
}

// ─── EvalResult ──────────────────────────────────────────────────────────────

// EvalResult is the outcome of evaluating one segment.
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

	// Compile deny_args_regex patterns.
	for toolName, tp := range p.Tools {
		for subName, sp := range tp.Subcommands {
			for _, pattern := range sp.DenyArgsRegex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("tool %q subcommand %q: invalid deny_args_regex %q: %w",
						toolName, subName, pattern, err)
				}
				sp.denyArgsRe = append(sp.denyArgsRe, re)
			}
		}
	}

	return &p, nil
}

// ─── Evaluate ────────────────────────────────────────────────────────────────

// Evaluate applies the policy to a single parsed segment and returns a decision.
//
// Evaluation order:
//  1. Tool must be in the Tools map; otherwise DefaultAction applies.
//  2. Flags are normalised via FlagAliases for this tool+subcommand.
//  3. The most specific SubcommandPolicy is selected (exact match → "*" → none).
//  4. deny_flags are checked.
//  5. deny_args_regex are checked against positional arguments.
//  6. The subcommand / tool / global action is returned.
func (p *Policy) Evaluate(seg shell.Segment) EvalResult {
	toolPolicy, ok := p.Tools[seg.Tool]
	if !ok {
		return EvalResult{
			Action: p.DefaultAction,
			Reason: fmt.Sprintf("tool %q is not listed in policy (default_action=%s)", seg.Tool, p.DefaultAction),
		}
	}

	// Normalise flags via alias table before matching.
	flags := p.normaliseFlags(seg.Tool, seg.Subcommand, seg.Flags)

	// Resolve the most specific subcommand policy.
	subPolicy := toolPolicy.Subcommands[seg.Subcommand]
	if subPolicy == nil {
		subPolicy = toolPolicy.Subcommands["*"]
	}

	if subPolicy == nil {
		// No subcommand policy found; use tool default.
		action := coalesce(toolPolicy.DefaultAction, p.DefaultAction)
		return EvalResult{
			Action: action,
			Reason: fmt.Sprintf("no subcommand policy for `%s %s` (tool default=%s)", seg.Tool, seg.Subcommand, action),
		}
	}

	// 1. Check deny_flags.
	for _, flag := range flags {
		for _, denied := range subPolicy.DenyFlags {
			if flag == denied {
				return EvalResult{
					Action: ActionDeny,
					Reason: fmt.Sprintf("flag %q is denied for `%s %s`", flag, seg.Tool, seg.Subcommand),
				}
			}
		}
	}

	// 2. Check deny_args_regex against positional arguments.
	for _, arg := range seg.Args {
		for _, re := range subPolicy.denyArgsRe {
			if re.MatchString(arg) {
				return EvalResult{
					Action: ActionDeny,
					Reason: fmt.Sprintf("argument %q matches denied pattern /%s/ for `%s %s`",
						arg, re.String(), seg.Tool, seg.Subcommand),
				}
			}
		}
	}

	// 3. Return the resolved action.
	action := coalesce(subPolicy.Action, toolPolicy.DefaultAction, p.DefaultAction)
	return EvalResult{Action: action}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// normaliseFlags applies flag_aliases for the given tool+subcommand, mapping
// short flags to their canonical long form.
func (p *Policy) normaliseFlags(tool, subcommand string, flags []string) []string {
	aliases := p.aliasMap(tool, subcommand)
	if len(aliases) == 0 {
		return flags
	}
	result := make([]string, len(flags))
	for i, f := range flags {
		if canonical, ok := aliases[f]; ok {
			result[i] = canonical
		} else {
			result[i] = f
		}
	}
	return result
}

func (p *Policy) aliasMap(tool, subcommand string) map[string]string {
	if p.FlagAliases == nil {
		return nil
	}
	subMap, ok := p.FlagAliases[tool]
	if !ok {
		return nil
	}
	return subMap[subcommand]
}

// coalesce returns the first non-empty Action from the list.
func coalesce(actions ...Action) Action {
	for _, a := range actions {
		if a != "" {
			return a
		}
	}
	return ActionDeny
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
