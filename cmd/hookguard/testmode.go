package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/afry23/hookguard/internal/policy"
)

// supportedTestTools lists the tool names accepted by hookguard test testfile
// lines. apply_patch is intentionally excluded: its multi-line patch text
// doesn't fit the one-line "Tool: Value -> decision" format and is covered by
// Go unit tests instead.
var supportedTestTools = map[string]bool{
	"Bash":       true,
	"PowerShell": true,
	"Read":       true,
	"Edit":       true,
	"Write":      true,
	"Glob":       true,
	"Grep":       true,
	"LS":         true,
	"WebFetch":   true,
	"WebSearch":  true,
}

// testCase is one parsed line from a hookguard test testfile.
type testCase struct {
	Line     int
	Raw      string
	Tool     string
	Value    string
	Expected policy.Action
}

// testFileParseError reports a malformed line found while parsing a testfile.
type testFileParseError struct {
	Line   int
	Reason string
}

func (e *testFileParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// parseTestFile parses every line of r into test cases. Comments (lines whose
// trimmed content starts with "#") and blank lines are skipped. Parsing stops
// at the first malformed line: no test case runs if any line fails to parse.
func parseTestFile(r io.Reader) ([]testCase, error) {
	var cases []testCase
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		tc, err := parseTestLine(trimmed, lineNo)
		if err != nil {
			return nil, err
		}
		cases = append(cases, tc)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cases, nil
}

// parseTestLine parses one non-empty, non-comment, already-trimmed line into
// a testCase.
func parseTestLine(raw string, lineNo int) (testCase, error) {
	colonIdx := strings.Index(raw, ":")
	if colonIdx == -1 {
		return testCase{}, &testFileParseError{Line: lineNo, Reason: "missing ':' after tool name"}
	}
	tool := strings.TrimSpace(raw[:colonIdx])
	if !supportedTestTools[tool] {
		return testCase{}, &testFileParseError{Line: lineNo, Reason: fmt.Sprintf("unsupported tool %q", tool)}
	}

	rest := raw[colonIdx+1:]
	sepIdx := strings.LastIndex(rest, " -> ")
	if sepIdx == -1 {
		return testCase{}, &testFileParseError{Line: lineNo, Reason: "missing ' -> ' separator"}
	}
	value := strings.TrimSpace(rest[:sepIdx])
	decisionStr := strings.TrimSpace(rest[sepIdx+len(" -> "):])

	var expected policy.Action
	switch decisionStr {
	case "allow":
		expected = policy.ActionAllow
	case "deny":
		expected = policy.ActionDeny
	case "ask":
		expected = policy.ActionAsk
	default:
		return testCase{}, &testFileParseError{Line: lineNo, Reason: fmt.Sprintf("invalid decision %q (want allow/deny/ask)", decisionStr)}
	}

	return testCase{
		Line:     lineNo,
		Raw:      raw,
		Tool:     tool,
		Value:    value,
		Expected: expected,
	}, nil
}

// toolInputFor builds the tool_input map decide() expects for tool, given the
// test line's value string.
func toolInputFor(tool, value string) map[string]any {
	switch tool {
	case "Bash", "PowerShell":
		return map[string]any{"command": value}
	case "Read", "Edit", "Write":
		return map[string]any{"file_path": value}
	case "Glob":
		return map[string]any{"pattern": value}
	case "Grep":
		return map[string]any{"pattern": value}
	case "LS":
		return map[string]any{"path": value}
	case "WebFetch":
		return map[string]any{"url": value}
	case "WebSearch":
		return map[string]any{"query": value}
	default:
		return map[string]any{}
	}
}

// hostFromFlag validates the --host flag value. Unlike parseHost (which
// silently defaults on typos for backward compatibility with bare hookguard
// invocations), an invalid --host value here is a user error and must fail.
func hostFromFlag(s string) (host, error) {
	switch s {
	case "claude":
		return hostClaude, nil
	case "codex":
		return hostCodex, nil
	default:
		return "", fmt.Errorf("invalid --host %q (want claude or codex)", s)
	}
}

// testModeFlagsWithValue lists the flag names runTestMode accepts, each of
// which consumes one following argument as its value (unless given as
// --flag=value). Needed by reorderFlagsFirst.
var testModeFlagsWithValue = map[string]bool{
	"-policy": true, "--policy": true,
	"-host": true, "--host": true,
}

// reorderFlagsFirst moves recognized flags (and their values) ahead of
// positional arguments, preserving relative order within each group.
// stdlib flag.Parse stops scanning at the first non-flag argument, so
// without this a testfile path given before --policy/--host (as the CLI's
// own usage examples show, e.g. `hookguard test file.txt --policy p.yaml`)
// would silently leave those flags unparsed.
func reorderFlagsFirst(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := a
		if eq := strings.Index(a, "="); eq != -1 {
			name = a[:eq]
		}
		if !testModeFlagsWithValue[name] {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if !strings.Contains(a, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// runTestMode implements the `hookguard test <testfile>` subcommand. It
// returns the process exit code instead of calling os.Exit so it can be unit
// tested without a subprocess.
func runTestMode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hookguard test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyFlag := fs.String("policy", "", "override policy file path")
	hostFlag := fs.String("host", "claude", "simulated host: claude or codex")
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "hookguard: usage: hookguard test <testfile> [--policy <path>] [--host claude|codex]")
		return 1
	}
	testFilePath := fs.Arg(0)

	h, err := hostFromFlag(*hostFlag)
	if err != nil {
		fmt.Fprintf(stderr, "hookguard: %v\n", err)
		return 1
	}

	f, err := os.Open(testFilePath)
	if err != nil {
		fmt.Fprintf(stderr, "hookguard: opening test file: %v\n", err)
		return 1
	}
	defer f.Close()

	cases, err := parseTestFile(f)
	if err != nil {
		fmt.Fprintf(stderr, "hookguard: %v\n", err)
		return 1
	}

	policyPath := *policyFlag
	if policyPath == "" {
		policyPath = resolvePolicyPath(h)
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "hookguard: loading policy %q: %v\n", policyPath, err)
		return 1
	}

	passed := 0
	for _, tc := range cases {
		input := hookInput{
			ToolName:  tc.Tool,
			ToolInput: toolInputFor(tc.Tool, tc.Value),
		}
		action, reason := decide(input, pol, h)
		if action == tc.Expected {
			passed++
			fmt.Fprintf(stdout, "PASS line %d: %s\n", tc.Line, tc.Raw)
		} else {
			fmt.Fprintf(stdout, "FAIL line %d: %s\n", tc.Line, tc.Raw)
			fmt.Fprintf(stdout, "     expected %s, got %s: %s\n", tc.Expected, action, reason)
		}
	}

	fmt.Fprintf(stdout, "%d/%d passed\n", passed, len(cases))
	if passed == len(cases) {
		return 0
	}
	return 1
}
