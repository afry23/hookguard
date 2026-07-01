// Package powershell parses PowerShell (7+) command strings into structured
// segments suitable for policy evaluation, mirroring internal/shell's role
// for Bash. Unlike internal/shell, this is a hand-written tokenizer scoped
// to the security-relevant subset of PowerShell syntax (cmdlet calls,
// operators, known-dangerous constructs) rather than full grammar fidelity
// -- no maintained Go library exists to parse PowerShell into an AST.
// See docs/adr/0005-hand-written-powershell-tokenizer.md.
package powershell

import (
	"strings"
	"unicode"
)

// Segment represents a single cmdlet invocation extracted from a (possibly
// compound) PowerShell expression such as "Get-A | Get-B; Get-C".
type Segment struct {
	Cmdlet     string            // canonical cmdlet name, e.g. "Remove-Item" (aliases resolved)
	Parameters map[string]string // named parameters with a value, e.g. {"Uri": "http://..."}
	Switches   []string          // named parameters with no value, e.g. ["Force", "Recurse"]
	Args       []string          // positional (unnamed) arguments
}

// ParseResult holds all segments extracted from the command and an opaque
// execution marker. A single command string may produce multiple segments
// when it contains pipelines, statement separators, or nested subexpressions
// / script blocks.
type ParseResult struct {
	Segments      []Segment
	HasOpaqueExec bool
	OpaqueReason  string
}

// aliases maps built-in PowerShell command aliases to their canonical
// Verb-Noun cmdlet name. Not exhaustive -- covers common aliases, including
// ones that shadow the intent of Bash tools already referenced in policy
// examples. "foreach" is deliberately absent here: it is disambiguated from
// the `foreach` language keyword in buildSegment instead.
var aliases = map[string]string{
	"rm": "Remove-Item", "ri": "Remove-Item", "del": "Remove-Item",
	"erase": "Remove-Item", "rd": "Remove-Item", "rmdir": "Remove-Item",
	"curl": "Invoke-WebRequest", "iwr": "Invoke-WebRequest", "wget": "Invoke-WebRequest",
	"iex":  "Invoke-Expression",
	"kill": "Stop-Process", "spps": "Stop-Process",
	"gci": "Get-ChildItem", "ls": "Get-ChildItem", "dir": "Get-ChildItem",
	"cp": "Copy-Item", "copy": "Copy-Item", "cpi": "Copy-Item",
	"mv": "Move-Item", "move": "Move-Item", "mi": "Move-Item",
	"cat": "Get-Content", "type": "Get-Content", "gc": "Get-Content",
	"icm":   "Invoke-Command",
	"saps":  "Start-Process", "start": "Start-Process",
	"ii":    "Invoke-Item",
	"%":     "ForEach-Object",
	"where": "Where-Object", "?": "Where-Object",
}

// opaqueCmdlets are cmdlets that execute dynamically constructed code and
// therefore cannot be safely analysed statically.
var opaqueCmdlets = map[string]string{
	"Invoke-Expression": "Invoke-Expression evaluates arbitrary strings as PowerShell code",
	"Add-Type":          "Add-Type compiles and loads arbitrary code",
}

// controlKeywords are language control structures, treated wholesale as
// opaque, mirroring the Bash parser's stance on if/while/for/case. "foreach"
// is intentionally excluded: it is ambiguous with the ForEach-Object alias
// and is handled specially in buildSegment.
var controlKeywords = map[string]bool{
	"if": true, "elseif": true, "else": true, "while": true, "for": true,
	"switch": true, "do": true, "until": true, "try": true, "catch": true,
	"finally": true,
}

// Parse tokenises a PowerShell command string into segments.
func Parse(command string) (*ParseResult, error) {
	if strings.TrimSpace(command) == "" {
		return &ParseResult{}, nil
	}
	return parseBlock(command), nil
}

// ─── block-level parsing ─────────────────────────────────────────────────────

// parseBlock parses one statement-list (the whole command, or the body of a
// $(...) subexpression / {...} script block found while scanning). It splits
// on top-level ';', newline, single '|', and '&&', building one Segment per
// command and recursing into any nested subexpressions/script blocks found
// along the way.
func parseBlock(src string) *ParseResult {
	r := []rune(src)
	res := &ParseResult{}

	var words []wordResult

	flush := func() {
		if len(words) == 0 {
			return
		}
		w := words
		words = nil

		seg, opaque, reason, nested := buildSegment(w)
		if opaque {
			res.HasOpaqueExec = true
			res.OpaqueReason = reason
			return
		}
		if seg != nil {
			res.Segments = append(res.Segments, *seg)
		}
		for _, block := range nested {
			sub := parseBlock(block)
			if sub.HasOpaqueExec {
				res.HasOpaqueExec = true
				res.OpaqueReason = sub.OpaqueReason
				return
			}
			res.Segments = append(res.Segments, sub.Segments...)
		}
	}

	i := 0
	for i < len(r) && !res.HasOpaqueExec {
		c := r[i]
		switch {
		case c == '#':
			for i < len(r) && r[i] != '\n' {
				i++
			}

		case unicode.IsSpace(c):
			i++

		case c == ';' || c == '\n':
			flush()
			i++

		case c == '|':
			flush()
			i++

		case c == '&':
			if i+1 < len(r) && r[i+1] == '&' {
				flush()
				i += 2
				continue
			}
			if len(words) == 0 {
				// Call operator prefix: "& <target> args...".
				i++
				for i < len(r) && unicode.IsSpace(r[i]) {
					i++
				}
				wr, ni := scanWord(r, i)
				i = ni
				if wr.Dynamic || len(wr.SubBlocks) > 0 {
					res.HasOpaqueExec = true
					res.OpaqueReason = "call operator (&) with dynamic/expression target"
					return res
				}
				words = append(words, wr)
			} else {
				// Trailing background operator: doesn't change what runs.
				flush()
				i++
			}

		default:
			wr, ni := scanWord(r, i)
			i = ni
			words = append(words, wr)
		}
	}
	if !res.HasOpaqueExec {
		flush()
	}

	return res
}

// buildSegment converts the words of one command into a Segment. Returns
// (nil, false, "", nested) for empty/inert (non-invocation) commands,
// (nil, true, reason, nil) when the command is opaque, or (*Segment, false,
// "", nested) on success. nested holds raw source of any $(...) subexpressions
// or {...} script blocks found in the words, to be parsed recursively by the
// caller.
func buildSegment(words []wordResult) (*Segment, bool, string, []string) {
	if len(words) == 0 {
		return nil, false, "", nil
	}

	// Strip a simple assignment prefix ("$var = ...", "$var += ...") so the
	// right-hand side is evaluated as the actual command. A bare variable
	// reference has an empty Text (nothing literal was scanned) and
	// Dynamic=true; that's the signature of "$var" in command position.
	if len(words) >= 2 && words[0].Dynamic && words[0].Text == "" && len(words[0].SubBlocks) == 0 && isAssignOp(words[1].Text) {
		words = words[2:]
		if len(words) == 0 {
			return nil, false, "", nil
		}
	}

	first := words[0]
	name := first.Text
	lower := strings.ToLower(name)

	var nested []string
	for _, w := range words {
		nested = append(nested, w.SubBlocks...)
	}

	// "foreach" is ambiguous: `foreach ($x in $y) {...}` is the opaque
	// control-flow keyword, `foreach { ... }` (piped) is the ForEach-Object
	// alias, which we recurse into instead of treating as opaque.
	if lower == "foreach" {
		if len(words) >= 2 && strings.HasPrefix(words[1].Text, "(") {
			return nil, true, "PowerShell control structure detected: foreach", nil
		}
		name = "ForEach-Object"
		lower = "foreach-object"
	} else if controlKeywords[lower] {
		return nil, true, "PowerShell control structure detected: " + name, nil
	}

	if name == "." {
		return nil, true, "dot-sourcing executes a script in the current scope", nil
	}

	if first.Dynamic {
		// A bare variable/expression in command position ("$cmd arg", not
		// invoked via "&" or "."): a value/property access, not a call.
		return nil, false, "", nested
	}

	canonical := name
	if alias, ok := aliases[lower]; ok {
		canonical = alias
	}

	if reason, isOpaque := opaqueCmdlets[canonical]; isOpaque {
		return nil, true, reason, nil
	}

	seg := &Segment{Cmdlet: canonical, Parameters: map[string]string{}}

	for i := 1; i < len(words); i++ {
		w := words[i]
		if strings.HasPrefix(w.Text, "-") && len(w.Text) > 1 {
			paramName := strings.TrimPrefix(w.Text, "-")
			if isEncodedCommandParam(canonical, paramName) {
				return nil, true, "-EncodedCommand hides the executed script from static analysis", nil
			}
			if i+1 < len(words) && words[i+1].Text != "" && !strings.HasPrefix(words[i+1].Text, "-") {
				seg.Parameters[paramName] = words[i+1].Text
				i++
				continue
			}
			seg.Switches = append(seg.Switches, paramName)
			continue
		}
		seg.Args = append(seg.Args, w.Text)
	}

	return seg, false, "", nested
}

// isAssignOp reports whether s is a PowerShell assignment operator.
func isAssignOp(s string) bool {
	switch s {
	case "=", "+=", "-=", "*=", "/=", "%=":
		return true
	}
	return false
}

// isEncodedCommandParam reports whether paramName (with the leading '-'
// already stripped) is an -EncodedCommand parameter. Full names are
// recognised regardless of cmdlet, since they are unambiguous; the short
// forms ("-e"/"-ec") are only recognised for cmdlets/executables that
// genuinely accept them, to avoid flagging unrelated single-letter flags.
// Being overly broad here is safe -- it only escalates to the opaque guard
// (ask/deny), never a silent allow.
func isEncodedCommandParam(cmdlet, paramName string) bool {
	lower := strings.ToLower(paramName)
	if lower == "encodedcommand" || lower == "enc" {
		return true
	}
	if lower == "e" || lower == "ec" {
		switch strings.ToLower(cmdlet) {
		case "pwsh", "pwsh.exe", "powershell", "powershell.exe", "start-process", "invoke-command":
			return true
		}
	}
	return false
}

// ─── word-level scanning ─────────────────────────────────────────────────────

// wordResult is one whitespace-delimited PowerShell token.
type wordResult struct {
	Text      string   // best-effort literal value (quotes resolved, escapes applied)
	Dynamic   bool     // contains a bare/unresolved variable reference ($var, ${var})
	SubBlocks []string // raw source of any $(...) subexpressions or {...} script blocks found
}

// isSeparatorRune reports whether r stops word scanning at the top level.
func isSeparatorRune(r rune) bool {
	switch r {
	case ';', '|', '&', '#':
		return true
	}
	return false
}

// scanWord scans one word starting at r[i] (i must not be on whitespace),
// handling single/double quoting, backtick escapes, variable references,
// $(...) subexpressions, and {...} script blocks. It returns the resolved
// word and the index just past it.
//
// Known limitation: bare (unprefixed) parentheses used for grouping (e.g. in
// `if (...)` conditions) are not depth-tracked -- only `$(...)` is recognised
// as a parenthesised construct. This can misparse separator characters
// nested inside such groupings; per ADR 0005 this parser targets the
// security-relevant subset of PowerShell syntax, not full grammar fidelity,
// and any resulting misparse only ever biases toward stricter handling.
func scanWord(r []rune, i int) (wordResult, int) {
	var wr wordResult
	var sb strings.Builder

	for i < len(r) {
		c := r[i]
		if isSeparatorRune(c) || unicode.IsSpace(c) {
			break
		}

		switch c {
		case '\'':
			i++
			for i < len(r) {
				if r[i] == '\'' {
					if i+1 < len(r) && r[i+1] == '\'' {
						sb.WriteRune('\'')
						i += 2
						continue
					}
					i++
					break
				}
				sb.WriteRune(r[i])
				i++
			}

		case '"':
			i++
			for i < len(r) {
				if r[i] == '`' && i+1 < len(r) {
					sb.WriteRune(r[i+1])
					i += 2
					continue
				}
				if r[i] == '"' {
					i++
					break
				}
				if r[i] == '$' {
					sub, dyn, ni := scanDollar(r, i)
					if sub != "" {
						wr.SubBlocks = append(wr.SubBlocks, sub)
					}
					if dyn {
						wr.Dynamic = true
					}
					i = ni
					continue
				}
				sb.WriteRune(r[i])
				i++
			}

		case '`':
			if i+1 < len(r) {
				sb.WriteRune(r[i+1])
				i += 2
			} else {
				i++
			}

		case '$':
			sub, dyn, ni := scanDollar(r, i)
			if sub != "" {
				wr.SubBlocks = append(wr.SubBlocks, sub)
			}
			if dyn {
				wr.Dynamic = true
			}
			i = ni

		case '{':
			block, ni := scanBraceBlock(r, i)
			wr.SubBlocks = append(wr.SubBlocks, block)
			i = ni

		default:
			sb.WriteRune(c)
			i++
		}
	}

	wr.Text = sb.String()
	return wr, i
}

// scanDollar scans a '$' construct: "$(...)" subexpression, "${name}" braced
// variable, or a bare "$name" variable reference. For a subexpression, it
// returns the raw inner source (to be parsed recursively) and dynamic=false,
// since the content is evaluated on its own merits rather than blanket-opaque
// (see ADR 0005). For a variable reference, it returns dynamic=true and no
// sub-block, since its value cannot be resolved statically.
func scanDollar(r []rune, i int) (sub string, dynamic bool, next int) {
	if i+1 < len(r) && r[i+1] == '(' {
		depth := 1
		start := i + 2
		j := i + 2
		for j < len(r) && depth > 0 {
			switch r[j] {
			case '(':
				depth++
			case ')':
				depth--
			case '\'':
				j++
				for j < len(r) && r[j] != '\'' {
					j++
				}
			case '"':
				j++
				for j < len(r) && r[j] != '"' {
					if r[j] == '`' {
						j++
					}
					j++
				}
			}
			j++
		}
		end := j - 1
		if end < start {
			end = start
		}
		return string(r[start:end]), false, j
	}

	if i+1 < len(r) && r[i+1] == '{' {
		depth := 1
		j := i + 2
		for j < len(r) && depth > 0 {
			switch r[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
			j++
		}
		return "", true, j
	}

	j := i + 1
	for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '_' || r[j] == ':') {
		j++
	}
	if j == i+1 {
		return "", false, i + 1
	}
	return "", true, j
}

// scanBraceBlock scans a balanced {...} script block starting at r[i] (which
// must be '{'), respecting nested braces and quotes. It returns the raw
// source *inside* the braces (for direct recursive parsing as a statement
// list -- the outer braces are stripped so parseBlock doesn't re-wrap it as
// another script-block sub-block) and the index just past the closing brace.
func scanBraceBlock(r []rune, i int) (string, int) {
	depth := 1
	start := i + 1
	j := i + 1
	for j < len(r) && depth > 0 {
		switch r[j] {
		case '{':
			depth++
		case '}':
			depth--
		case '\'':
			j++
			for j < len(r) && r[j] != '\'' {
				j++
			}
		case '"':
			j++
			for j < len(r) && r[j] != '"' {
				if r[j] == '`' {
					j++
				}
				j++
			}
		}
		j++
	}
	end := j - 1
	if end < start {
		end = start
	}
	return string(r[start:end]), j
}
