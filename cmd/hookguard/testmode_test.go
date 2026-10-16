package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afry23/hookguard/internal/policy"
)

// ─── parseTestLine ────────────────────────────────────────────────────────────

func TestParseTestLine_AllTools(t *testing.T) {
	tests := []struct {
		raw       string
		wantTool  string
		wantValue string
		wantDec   policy.Action
	}{
		{`Bash: git commit -m "Test Commit" --no-verify -> deny`, "Bash", `git commit -m "Test Commit" --no-verify`, policy.ActionDeny},
		{`PowerShell: Remove-Item -Recurse -Force C:\ -> ask`, "PowerShell", `Remove-Item -Recurse -Force C:\`, policy.ActionAsk},
		{`Read: /app/.env -> deny`, "Read", "/app/.env", policy.ActionDeny},
		{`Edit: /app/main.go -> allow`, "Edit", "/app/main.go", policy.ActionAllow},
		{`Write: secrets/api_key.txt -> deny`, "Write", "secrets/api_key.txt", policy.ActionDeny},
		{`Glob: **/*.pem -> deny`, "Glob", "**/*.pem", policy.ActionDeny},
		{`Grep: password -> ask`, "Grep", "password", policy.ActionAsk},
		{`LS: /etc -> allow`, "LS", "/etc", policy.ActionAllow},
		{`WebFetch: https://evil.example.com -> deny`, "WebFetch", "https://evil.example.com", policy.ActionDeny},
		{`WebSearch: internal roadmap 2026 -> ask`, "WebSearch", "internal roadmap 2026", policy.ActionAsk},
	}
	for _, tc := range tests {
		got, err := parseTestLine(tc.raw, 1)
		if err != nil {
			t.Fatalf("parseTestLine(%q) unexpected error: %v", tc.raw, err)
		}
		if got.Tool != tc.wantTool || got.Value != tc.wantValue || got.Expected != tc.wantDec {
			t.Errorf("parseTestLine(%q) = %+v, want tool=%s value=%s dec=%s", tc.raw, got, tc.wantTool, tc.wantValue, tc.wantDec)
		}
	}
}

func TestParseTestLine_ArrowInValue(t *testing.T) {
	// "->" inside the value (e.g. a Bash argument) must not confuse parsing;
	// splitting on the LAST " -> " keeps this safe.
	raw := `Bash: echo "a -> b" -> allow`
	got, err := parseTestLine(raw, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Value != `echo "a -> b"` || got.Expected != policy.ActionAllow {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestLine_UnknownTool(t *testing.T) {
	_, err := parseTestLine("apply_patch: foo -> deny", 5)
	if err == nil {
		t.Fatal("want error for unsupported tool")
	}
	var pe *testFileParseError
	if !errorsAs(err, &pe) {
		t.Fatalf("want *testFileParseError, got %T", err)
	}
	if pe.Line != 5 {
		t.Errorf("want line 5, got %d", pe.Line)
	}
}

func TestParseTestLine_MissingColon(t *testing.T) {
	_, err := parseTestLine("Bash git status -> allow", 1)
	if err == nil {
		t.Fatal("want error for missing ':'")
	}
}

func TestParseTestLine_MissingArrow(t *testing.T) {
	_, err := parseTestLine("Bash: git status", 1)
	if err == nil {
		t.Fatal("want error for missing ' -> '")
	}
}

func TestParseTestLine_InvalidDecision(t *testing.T) {
	_, err := parseTestLine("Bash: git status -> maybe", 1)
	if err == nil {
		t.Fatal("want error for invalid decision keyword")
	}
}

// errorsAs is a tiny local helper to avoid importing "errors" just for As
// with a concrete pointer type in tests.
func errorsAs(err error, target **testFileParseError) bool {
	pe, ok := err.(*testFileParseError)
	if !ok {
		return false
	}
	*target = pe
	return true
}

// ─── parseTestFile ────────────────────────────────────────────────────────────

func TestParseTestFile_CommentsAndBlankLines(t *testing.T) {
	content := `# comment
Bash: ls -la -> allow

  # indented comment
Read: /app/.env -> deny
`
	cases, err := parseTestFile(strings.NewReader(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("want 2 cases, got %d", len(cases))
	}
	if cases[0].Line != 2 || cases[1].Line != 5 {
		t.Errorf("want line numbers 2 and 5, got %d and %d", cases[0].Line, cases[1].Line)
	}
}

func TestParseTestFile_FailFast(t *testing.T) {
	content := `Bash: ls -la -> allow
Bash: bad line without arrow
Bash: git status -> allow
`
	cases, err := parseTestFile(strings.NewReader(content))
	if err == nil {
		t.Fatal("want error for malformed line 2")
	}
	if cases != nil {
		t.Errorf("want no cases returned on parse failure, got %v", cases)
	}
	pe, ok := err.(*testFileParseError)
	if !ok {
		t.Fatalf("want *testFileParseError, got %T", err)
	}
	if pe.Line != 2 {
		t.Errorf("want failure at line 2, got %d", pe.Line)
	}
}

// ─── hostFromFlag ─────────────────────────────────────────────────────────────

func TestHostFromFlag(t *testing.T) {
	if h, err := hostFromFlag("claude"); err != nil || h != hostClaude {
		t.Errorf("hostFromFlag(claude) = %v, %v", h, err)
	}
	if h, err := hostFromFlag("codex"); err != nil || h != hostCodex {
		t.Errorf("hostFromFlag(codex) = %v, %v", h, err)
	}
	if _, err := hostFromFlag("bogus"); err == nil {
		t.Error("want error for invalid --host value")
	}
}

// ─── runTestMode integration tests ───────────────────────────────────────────

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestRunTestMode_AllPass(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	testFile := writeTempFile(t, dir, "cases.txt", `Bash: git push --force origin main -> deny
Bash: git status -> allow
`)
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, testFile}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("want exit 0, got %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2/2 passed") {
		t.Errorf("want summary '2/2 passed', got:\n%s", stdout.String())
	}
}

func TestRunTestMode_OneFail(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	testFile := writeTempFile(t, dir, "cases.txt", `Bash: git push --force origin main -> allow
`)
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, testFile}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("want exit 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "FAIL line 1") {
		t.Errorf("want FAIL for line 1, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "0/1 passed") {
		t.Errorf("want '0/1 passed', got:\n%s", stdout.String())
	}
}

func TestRunTestMode_BrokenTestFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	testFile := writeTempFile(t, dir, "cases.txt", "NotATool: foo -> deny\n")
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, testFile}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("want exit 1, got %d", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("want no stdout output on parse failure, got:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "line 1") {
		t.Errorf("want parse error mentioning line 1 on stderr, got:\n%s", stderr.String())
	}
}

func TestRunTestMode_InvalidHost(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	testFile := writeTempFile(t, dir, "cases.txt", "Bash: git status -> allow\n")
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, "--host", "bogus", testFile}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("want exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "invalid --host") {
		t.Errorf("want invalid --host error, got:\n%s", stderr.String())
	}
}

func TestRunTestMode_MissingTestFileArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("want exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Errorf("want usage message, got:\n%s", stderr.String())
	}
}

func TestRunTestMode_PolicyOverride(t *testing.T) {
	dir := t.TempDir()
	// Custom policy where Bash defaults to allow, unlike testYAML's deny.
	policyPath := writeTempFile(t, dir, "custom.yaml", "version: 1\ndefault_action: allow\n")
	testFile := writeTempFile(t, dir, "cases.txt", "Bash: anything goes -> allow\n")
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, testFile}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("want exit 0, got %d; stderr=%s", code, stderr.String())
	}
}

func TestRunTestMode_DefaultPolicyResolution(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	t.Setenv("HOOKGUARD_POLICY", policyPath)
	testFile := writeTempFile(t, dir, "cases.txt", "Bash: git status -> allow\n")
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{testFile}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("want exit 0 via $HOOKGUARD_POLICY, got %d; stderr=%s", code, stderr.String())
	}
}

func TestRunTestMode_CodexAskDowngrade(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTempFile(t, dir, "hookguard.yaml", testYAML)
	// The cmdlet rule for Remove-Item yields "ask" under testYAML; under
	// --host codex it must downgrade to "deny".
	testFile := writeTempFile(t, dir, "cases.txt", `PowerShell: Remove-Item -Recurse -Force C:\ -> deny
`)
	var stdout, stderr bytes.Buffer
	code := runTestMode([]string{"--policy", policyPath, "--host", "codex", testFile}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("want exit 0 (ask downgraded to deny under codex), got %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
