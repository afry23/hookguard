package policy

import (
	"fmt"
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

	if len(r.Tools) > 0 {
		parts = append(parts, fmt.Sprintf(`tool_name in %s`, quotedList(r.Tools)))
		if r.Path != "" {
			if _, err := doublestar.Match(r.Path, ""); err != nil {
				return fmt.Errorf("invalid glob pattern %q: %w", r.Path, err)
			}
			parts = append(parts, fmt.Sprintf(`glob(tool_input.file_path, %q)`, r.Path))
		}
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
	r.scopeTools = scopeToolsFor(r)
	return nil
}

// validateRule enforces the sugar-field combination rules described in
// docs/CEL-Ruels-Plan.md.
func validateRule(r *Rule) error {
	if r.Tool != "" && len(r.Tools) > 0 {
		return fmt.Errorf("rule has both `tool` and `tools` set")
	}
	if (r.Subcommand != "" || len(r.DenyFlags) > 0) && r.Tool == "" {
		return fmt.Errorf("rule sets `subcommand`/`deny_flags` without `tool`")
	}
	if r.Path != "" && len(r.Tools) == 0 {
		return fmt.Errorf("rule sets `path` without `tools`")
	}
	if r.Tool == "" && len(r.Tools) == 0 && r.When == "" {
		return fmt.Errorf("rule has no condition (no `tool`, `tools`, or `when`)")
	}
	return nil
}

// scopeToolsFor derives the set of tool_name values a rule can possibly
// match, used to skip CEL evaluation entirely for irrelevant tool calls.
// Returns nil (meaning "evaluate for every tool_name") for raw when-only
// rules, since we cannot statically determine their scope.
func scopeToolsFor(r *Rule) map[string]bool {
	switch {
	case r.Tool != "":
		return map[string]bool{"Bash": true}
	case len(r.Tools) > 0:
		set := make(map[string]bool, len(r.Tools))
		for _, t := range r.Tools {
			set[t] = true
		}
		return set
	default:
		return nil
	}
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
