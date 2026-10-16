package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/google/cel-go/cel"
)

// compileRule validates a rule's sugar fields, builds the equivalent CEL
// source (ANDing in any raw When expression), compiles it against env, and
// caches the resulting program plus a scopeTools set on the rule.
func compileRule(r *Rule, env *cel.Env) error {
	if err := validateRule(r); err != nil {
		return err
	}

	var parts []string

	if r.Tool != "" {
		parts = append(parts, fmt.Sprintf(`tool_name == "Bash" && segment.tool == %q`, r.Tool))
		if r.Subcommand != "" {
			parts = append(parts, fmt.Sprintf(`segment.subcommand == %q`, r.Subcommand))
		}
		if len(r.DenyFlags) > 0 {
			parts = append(parts, fmt.Sprintf(`segment.flags.exists(f, f in %s)`, quotedList(r.DenyFlags)))
		}
	}

	if r.Cmdlet != "" {
		parts = append(parts, fmt.Sprintf(`tool_name == "PowerShell" && ps_segment.cmdlet == %q`, r.Cmdlet))
		if len(r.DenyFlags) > 0 {
			list := quotedList(r.DenyFlags)
			parts = append(parts, fmt.Sprintf(
				`(ps_segment.parameters.exists(k, k in %s) || ps_segment.switches.exists(f, f in %s))`,
				list, list,
			))
		}
	}

	if len(r.Tools) > 0 {
		expr, err := toolsExpr(r.Tools)
		if err != nil {
			return err
		}
		parts = append(parts, expr)
		if r.Path != "" {
			if !doublestar.ValidatePattern(r.Path) {
				return fmt.Errorf("invalid glob pattern %q", r.Path)
			}
			parts = append(parts, fmt.Sprintf(`glob(tool_input.file_path, %q)`, r.Path))
		}
		inputParts, err := inputExprs(r.Input)
		if err != nil {
			return err
		}
		parts = append(parts, inputParts...)
	}

	if r.When != "" {
		parts = append(parts, "("+r.When+")")
	}

	source := strings.Join(parts, " && ")

	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return fmt.Errorf("compiling CEL expression %q: %w", source, iss.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return fmt.Errorf("building CEL program for %q: %w", source, err)
	}

	r.program = prg
	r.scopeMatch = scopeMatchFor(r)
	return nil
}

// validateRule enforces the sugar-field combination rules described in
// docs/CEL-Ruels-Plan.md.
func validateRule(r *Rule) error {
	if r.Tool != "" && len(r.Tools) > 0 {
		return fmt.Errorf("rule has both `tool` and `tools` set")
	}
	if r.Tool != "" && r.Cmdlet != "" {
		return fmt.Errorf("rule has both `tool` and `cmdlet` set")
	}
	if r.Cmdlet != "" && len(r.Tools) > 0 {
		return fmt.Errorf("rule has both `cmdlet` and `tools` set")
	}
	if r.Subcommand != "" && r.Tool == "" {
		return fmt.Errorf("rule sets `subcommand` without `tool`")
	}
	if len(r.DenyFlags) > 0 && r.Tool == "" && r.Cmdlet == "" {
		return fmt.Errorf("rule sets `deny_flags` without `tool` or `cmdlet`")
	}
	if r.Path != "" && len(r.Tools) == 0 {
		return fmt.Errorf("rule sets `path` without `tools`")
	}
	if len(r.Input) > 0 && len(r.Tools) == 0 {
		return fmt.Errorf("rule sets `input` without `tools`")
	}
	switch r.OnError {
	case "", "ask", "skip":
	default:
		return fmt.Errorf("invalid on_error %q (want ask or skip)", r.OnError)
	}
	if r.Tool == "" && r.Cmdlet == "" && len(r.Tools) == 0 && r.When == "" {
		return fmt.Errorf("rule has no condition (no `tool`, `cmdlet`, `tools`, or `when`)")
	}
	return nil
}

// scopeMatchFor derives a predicate over tool_name values the rule can
// possibly match, used to skip CEL evaluation entirely for irrelevant tool
// calls. Returns nil (meaning "evaluate for every tool_name") for raw
// when-only rules, since we cannot statically determine their scope.
func scopeMatchFor(r *Rule) func(string) bool {
	switch {
	case r.Tool != "":
		return func(name string) bool { return name == "Bash" }
	case r.Cmdlet != "":
		return func(name string) bool { return name == "PowerShell" }
	case len(r.Tools) > 0:
		tools := append([]string(nil), r.Tools...)
		return func(name string) bool {
			for _, t := range tools {
				if toolPatternMatches(t, name) {
					return true
				}
			}
			return false
		}
	default:
		return nil
	}
}

// isGlob reports whether a tools: entry contains glob metacharacters.
func isGlob(s string) bool {
	return strings.ContainsAny(s, "*?[{")
}

// toolPatternMatches matches a tool_name against a tools: entry, which is
// either an exact name or a glob such as "mcp__github__*".
func toolPatternMatches(pattern, name string) bool {
	if !isGlob(pattern) {
		return pattern == name
	}
	ok, err := doublestar.Match(pattern, name)
	return err == nil && ok
}

// toolsExpr renders the CEL condition for a tools: list: exact names become
// an `in` test, glob entries become glob() calls, all ORed together.
func toolsExpr(tools []string) (string, error) {
	var exact []string
	var alts []string
	for _, t := range tools {
		if !isGlob(t) {
			exact = append(exact, t)
			continue
		}
		if !doublestar.ValidatePattern(t) {
			return "", fmt.Errorf("invalid glob pattern %q in tools", t)
		}
		alts = append(alts, fmt.Sprintf(`glob(tool_name, %q)`, t))
	}
	if len(exact) > 0 {
		alts = append([]string{fmt.Sprintf(`tool_name in %s`, quotedList(exact))}, alts...)
	}
	return "(" + strings.Join(alts, " || ") + ")", nil
}

// inputExprs renders one CEL condition per input: key. A missing key makes
// the condition false (the rule simply does not apply) instead of raising a
// runtime error. Values are compared as strings, so numbers and booleans can
// be matched too.
func inputExprs(input map[string]StringList) ([]string, error) {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []string
	for _, k := range keys {
		pats := input[k]
		if len(pats) == 0 {
			return nil, fmt.Errorf("input key %q has no patterns", k)
		}
		alts := make([]string, len(pats))
		for i, p := range pats {
			if !doublestar.ValidatePattern(p) {
				return nil, fmt.Errorf("invalid glob pattern %q for input key %q", p, k)
			}
			alts[i] = fmt.Sprintf(`input_glob(tool_input[%q], %q)`, k, p)
		}
		out = append(out, fmt.Sprintf(`(%q in tool_input && (%s))`, k, strings.Join(alts, " || ")))
	}
	return out, nil
}

// quotedList renders a Go string slice as a CEL list literal of double-quoted
// string values, e.g. ["--force", "-f"].
func quotedList(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
