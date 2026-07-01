// Package shell parses shell command strings into structured segments
// suitable for policy evaluation.
package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Segment represents a single command extracted from a (possibly compound)
// shell expression such as "cmd1 && cmd2 | cmd3".
type Segment struct {
	Tool       string   // primary executable, e.g. "git"
	Subcommand string   // first non-flag argument, e.g. "push"
	Flags      []string // individual flags, normalised (see expandFlags)
	Args       []string // non-flag positional arguments (excluding Subcommand)
}

// ParseResult holds all segments extracted from the command and an opaque
// execution marker.  A single command string may produce multiple segments
// when it contains pipelines or boolean operators (&&, ||, ;).
type ParseResult struct {
	Segments      []Segment
	HasOpaqueExec bool
	OpaqueReason  string
}

// opaqueTools are commands that execute arbitrary strings and therefore
// cannot be safely analysed statically.
var opaqueTools = map[string]string{
	"eval":   "eval executes arbitrary strings as shell code",
	"exec":   "exec replaces the current process",
	"source": "source executes a file in the current shell",
	".":      ". executes a file in the current shell",
	"xargs":  "xargs constructs and runs commands from stdin at runtime",
}

// shellInterpreters are programs that accept a -c flag to run arbitrary code.
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true,
}

// Parse tokenises a shell command string into segments.
// It uses a proper POSIX shell parser (mvdan.cc/sh/v3) so quoting, pipelines,
// and compound operators are respected correctly.
func Parse(command string) (*ParseResult, error) {
	if strings.TrimSpace(command) == "" {
		return &ParseResult{}, nil
	}

	f, err := syntax.NewParser().Parse(strings.NewReader(command), "cmd")
	if err != nil {
		// Unparseable shell → treat conservatively as opaque.
		return &ParseResult{
			HasOpaqueExec: true,
			OpaqueReason:  "shell parse error: " + err.Error(),
		}, nil
	}

	result := &ParseResult{}

	syntax.Walk(f, func(node syntax.Node) bool {
		if result.HasOpaqueExec {
			return false // short-circuit once we know it's opaque
		}

		switch n := node.(type) {
		case *syntax.CmdSubst:
			// $(...) or backtick substitution — dynamic command execution.
			result.HasOpaqueExec = true
			result.OpaqueReason = "command substitution $(...) detected"
			return false

		case *syntax.ArithmCmd, *syntax.ArithmExp:
			result.HasOpaqueExec = true
			result.OpaqueReason = "arithmetic command/expression detected"
			return false

		case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
			result.HasOpaqueExec = true
			result.OpaqueReason = "complex shell control structure detected"
			return false

		case *syntax.CallExpr:
			seg, opaque, reason := callToSegment(n)
			if opaque {
				result.HasOpaqueExec = true
				result.OpaqueReason = reason
				return false
			}
			if seg != nil {
				result.Segments = append(result.Segments, *seg)
			}
			// Do not recurse into args — CmdSubst inside args is already
			// caught by wordToString returning isDynamic=true.
			return false
		}

		return true
	})

	return result, nil
}

// callToSegment converts a parsed CallExpr into a Segment.
// Returns (nil, false, "") for empty calls, (nil, true, reason) when the
// call is considered opaque, or (*Segment, false, "") on success.
func callToSegment(call *syntax.CallExpr) (*Segment, bool, string) {
	if len(call.Args) == 0 {
		return nil, false, ""
	}

	// Extract literal word values.  Any dynamic content (variables,
	// substitutions, globs) causes the segment to be treated as opaque.
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		lit, isDynamic := wordToString(w)
		if isDynamic {
			return nil, true, "dynamic content in command word (variable or substitution)"
		}
		words = append(words, lit)
	}

	if len(words) == 0 {
		return nil, false, ""
	}

	tool := words[0]

	// Hardcoded opaque tools.
	if reason, isOpaque := opaqueTools[tool]; isOpaque {
		return nil, true, reason
	}

	// Shell interpreters are opaque when called with -c.
	if shellInterpreters[tool] {
		for _, w := range words[1:] {
			if w == "-c" {
				return nil, true, tool + " -c executes arbitrary code"
			}
		}
	}

	// env wrapping another command is opaque because we cannot inspect the
	// wrapped command without also knowing which VAR=val assignments precede it.
	if tool == "env" {
		for _, w := range words[1:] {
			if !strings.Contains(w, "=") && !strings.HasPrefix(w, "-") {
				return nil, true, "env wrapping command: " + w
			}
		}
	}

	seg := &Segment{Tool: tool}
	pastDoubleDash := false
	subFound := false

	for _, w := range words[1:] {
		if pastDoubleDash {
			seg.Args = append(seg.Args, w)
			continue
		}
		if w == "--" {
			pastDoubleDash = true
			continue
		}
		if strings.HasPrefix(w, "-") {
			seg.Flags = append(seg.Flags, expandFlags(w)...)
		} else if !subFound {
			seg.Subcommand = w
			subFound = true
		} else {
			seg.Args = append(seg.Args, w)
		}
	}

	return seg, false, ""
}

// wordToString extracts the literal string value of a shell Word.
// isDynamic is true when the word contains variables, substitutions,
// or other constructs that cannot be resolved without execution.
func wordToString(w *syntax.Word) (value string, isDynamic bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			// Only purely literal double-quoted strings are safe.
			for _, dp := range p.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				} else {
					return "", true // e.g. "$var" or "$(cmd)"
				}
			}
		default:
			// ParamExp ($var), CmdSubst ($(...)), ProcSubst (<(...)), etc.
			return "", true
		}
	}
	return sb.String(), false
}

// expandFlags normalises a flag token:
//   - "--flag=value"  →  ["--flag"]          (strips value)
//   - "-abc"          →  ["-a", "-b", "-c"]  (expands combined short flags)
//   - "-x" / "--flag" →  unchanged
func expandFlags(flag string) []string {
	if strings.HasPrefix(flag, "--") {
		if idx := strings.IndexByte(flag, '='); idx != -1 {
			return []string{flag[:idx]}
		}
		return []string{flag}
	}
	// Combined short flags: -rf → ["-r", "-f"]
	// Note: flags that take a value argument (e.g. -m "msg") should not be
	// combined in practice; this expansion errs on the safe side.
	if strings.HasPrefix(flag, "-") && len(flag) > 2 {
		result := make([]string, 0, len(flag)-1)
		for _, c := range flag[1:] {
			result = append(result, "-"+string(c))
		}
		return result
	}
	return []string{flag}
}
