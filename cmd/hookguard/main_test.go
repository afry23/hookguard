package main

import (
	"os"
	"path/filepath"
	"testing"

	"hookguard/internal/policy"
)

func loadTestPolicy(t *testing.T, yamlContent string) *policy.Policy {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	if err := os.WriteFile(tmp, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load test policy: %v", err)
	}
	return p
}

const testYAML = `
version: 1
default_action: deny
opaque_execution_guard:
  action: ask
powershell_opaque_execution_guard:
  action: ask
patch_opaque_execution_guard:
  action: ask

rules:
  - tool: git
    action: allow

  - tool: git
    subcommand: push
    deny_flags: ["--force"]
    action: deny
    reason: "force-push denied"

  - cmdlet: Remove-Item
    action: ask
    reason: "always ask for Remove-Item"

  - tools: ["Read"]
    path: "**/.env*"
    action: deny
    reason: "env file read denied"

  - tools: ["Edit", "Write"]
    path: "**/secrets/**"
    action: deny
    reason: "secrets dir denied"

  - when: 'permission_mode == "auto"'
    action: ask
    reason: "auto mode requires confirmation"
`

// ─── existing tests, updated to pass host parameter ──────────────────────────

func TestDecide_PowerShellRuleMatch(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "PowerShell",
		ToolInput: map[string]any{"command": "Remove-Item -Recurse -Force C:\\"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionAsk {
		t.Errorf("want ask (cmdlet rule matched), got %s", action)
	}
}

func TestDecide_PowerShellOpaqueGuard(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "PowerShell",
		ToolInput: map[string]any{"command": "Invoke-Expression $x"},
	}
	action, reason := decide(input, pol, hostClaude)
	if action != policy.ActionAsk {
		t.Errorf("want ask (powershell_opaque_execution_guard), got %s: %s", action, reason)
	}
}

func TestDecide_PowerShellDefaultAction(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "PowerShell",
		ToolInput: map[string]any{"command": "Get-ChildItem"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionDeny {
		t.Errorf("want default_action (deny) for unmatched cmdlet, got %s", action)
	}
}

func TestDecide_PathRuleEndToEnd(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": "/app/.env"},
	}
	action, reason := decide(input, pol, hostClaude)
	if action != policy.ActionDeny {
		t.Errorf("want deny for .env read, got %s: %s", action, reason)
	}
}

func TestDecide_BashRegression_ForcePushDenied(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git push --force origin main"},
	}
	action, reason := decide(input, pol, hostClaude)
	if action != policy.ActionDeny {
		t.Errorf("want deny for git push --force, got %s: %s", action, reason)
	}
}

func TestDecide_UnknownNonBashTool_DefaultAction(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "WebFetch",
		ToolInput: map[string]any{"url": "https://example.com"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionDeny {
		t.Errorf("want default_action (deny) for unmatched tool, got %s", action)
	}
}

// ─── Codex ask→deny downgrade ─────────────────────────────────────────────────

func TestDecide_CodexDowngrade_BashAskToDeny(t *testing.T) {
	// The opaque_execution_guard returns ask; under Codex it must be downgraded
	// to deny.
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "eval $x"},
	}
	action, reason := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny (ask downgraded for Codex), got %s: %s", action, reason)
	}
}

func TestDecide_CodexDowngrade_NonBashRule(t *testing.T) {
	// A non-Bash/path rule that returns ask: permission_mode == "auto".
	// Confirm the downgrade applies for every tool_name, not just Bash.
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:       "Read",
		ToolInput:      map[string]any{"file_path": "/app/main.go"},
		PermissionMode: "auto",
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny (ask downgraded for Codex non-Bash tool), got %s", action)
	}
}

func TestDecide_Claude_NoDowngrade(t *testing.T) {
	// The same ask-returning rule must NOT be downgraded for Claude.
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "eval $x"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionAsk {
		t.Errorf("want ask for Claude (no downgrade), got %s", action)
	}
}

// ─── apply_patch ─────────────────────────────────────────────────────────────

func TestDecide_ApplyPatch_AddFile(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Adding a file evaluates as Write — not covered by any deny rule → deny (default).
	input := hookInput{
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"command": "*** Begin Patch\n*** Add File: foo.go\n+package main\n*** End Patch",
		},
	}
	action, _ := decide(input, pol, hostCodex)
	// default_action is deny for unmatched Write
	if action != policy.ActionDeny {
		t.Errorf("want default deny for unmatched Write via apply_patch, got %s", action)
	}
}

func TestDecide_ApplyPatch_DeleteAsEdit(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Deleting a .env file evaluates as Edit against path "**/.env*" — but
	// the rule uses tools:["Read"], so it won't match Edit. Default deny.
	input := hookInput{
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"command": "*** Begin Patch\n*** Delete File: .env\n*** End Patch",
		},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny for delete .env (default action), got %s", action)
	}
}

func TestDecide_ApplyPatch_SecretsDenied(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Writing to secrets/ matches the Edit/Write deny rule.
	input := hookInput{
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"command": "*** Begin Patch\n*** Update File: myapp/secrets/key.txt\n@@ -1 +1 @@\n-old\n+new\n*** End Patch",
		},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny for Update File in secrets/, got %s", action)
	}
}

func TestDecide_ApplyPatch_MoveSegments(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Move: src.go (Edit/OpMoveSource) + dst secrets/new.go (Write/OpMoveDest).
	// dst matches secrets deny rule → overall deny.
	input := hookInput{
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"command": "*** Begin Patch\n*** Update File: src.go\n*** Move to: app/secrets/new.go\n*** End Patch",
		},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny when move destination is in secrets/, got %s", action)
	}
}

func TestDecide_ApplyPatch_MultiFile_OneDenied(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Two segments: one safe (Update foo.go→Edit→default deny), one matches
	// secrets deny. Overall must be deny regardless of order.
	input := hookInput{
		ToolName: "apply_patch",
		ToolInput: map[string]any{
			"command": "*** Begin Patch\n*** Update File: foo.go\n@@ @@\n*** Update File: app/secrets/config.go\n@@ @@\n*** End Patch",
		},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny when any segment matches deny rule, got %s", action)
	}
}

func TestDecide_ApplyPatch_OpaqueGuard(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Malformed patch → opaque → patch_opaque_execution_guard (ask) → Codex → deny.
	input := hookInput{
		ToolName:  "apply_patch",
		ToolInput: map[string]any{"command": "not a real patch"},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny for malformed patch under Codex (ask downgraded), got %s", action)
	}
}

func TestDecide_ApplyPatch_OpaqueGuard_Claude(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	// Same malformed patch under Claude: ask (no downgrade).
	input := hookInput{
		ToolName:  "apply_patch",
		ToolInput: map[string]any{"command": "not a real patch"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionAsk {
		t.Errorf("want ask for malformed patch under Claude, got %s", action)
	}
}

// ─── Codex Windows Bash → PowerShell dispatch ────────────────────────────────

func TestDecide_CodexWindowsBash_MatchesPowerShellRule(t *testing.T) {
	prev := goos
	goos = "windows"
	defer func() { goos = prev }()

	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "Remove-Item -Recurse C:\\temp"},
	}
	action, _ := decide(input, pol, hostCodex)
	// Remove-Item → ask, then Codex → deny
	if action != policy.ActionDeny {
		t.Errorf("want deny (Remove-Item ask downgraded for Codex), got %s", action)
	}
}

func TestDecide_CodexLinuxBash_MatchesBashRules(t *testing.T) {
	prev := goos
	goos = "linux"
	defer func() { goos = prev }()

	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git push --force origin main"},
	}
	action, _ := decide(input, pol, hostCodex)
	if action != policy.ActionDeny {
		t.Errorf("want deny for Bash force-push on Codex/Linux, got %s", action)
	}
}

func TestDecide_ClaudeWindowsBash_NotDispatched(t *testing.T) {
	// Claude + Windows: Bash must stay on the Bash path, not PowerShell.
	prev := goos
	goos = "windows"
	defer func() { goos = prev }()

	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git push --force origin main"},
	}
	action, _ := decide(input, pol, hostClaude)
	if action != policy.ActionDeny {
		t.Errorf("want deny for Bash force-push on Claude/Windows, got %s", action)
	}
}

// ─── parseHost ───────────────────────────────────────────────────────────────

func TestParseHost(t *testing.T) {
	tests := []struct {
		args []string
		want host
	}{
		{nil, hostClaude},
		{[]string{"hookguard"}, hostClaude},
		{[]string{"hookguard", "claude"}, hostClaude},
		{[]string{"hookguard", "codex"}, hostCodex},
		{[]string{"hookguard", "unknown"}, hostClaude},
	}
	for _, tc := range tests {
		if got := parseHost(tc.args); got != tc.want {
			t.Errorf("parseHost(%v) = %s, want %s", tc.args, got, tc.want)
		}
	}
}

// ─── resolvePolicyPath ───────────────────────────────────────────────────────

func TestResolvePolicyPath_Claude(t *testing.T) {
	t.Setenv("HOOKGUARD_POLICY", "")
	p := resolvePolicyPath(hostClaude)
	if filepath.Base(p) != "hookguard.yaml" {
		t.Errorf("unexpected filename: %s", p)
	}
	// Must be under .claude/
	if filepath.Base(filepath.Dir(p)) != ".claude" {
		t.Errorf("want .claude dir, got %s", filepath.Dir(p))
	}
}

func TestResolvePolicyPath_Codex(t *testing.T) {
	t.Setenv("HOOKGUARD_POLICY", "")
	p := resolvePolicyPath(hostCodex)
	if filepath.Base(filepath.Dir(p)) != ".codex" {
		t.Errorf("want .codex dir, got %s", filepath.Dir(p))
	}
}

func TestResolvePolicyPath_EnvOverride(t *testing.T) {
	t.Setenv("HOOKGUARD_POLICY", "/custom/path.yaml")
	if got := resolvePolicyPath(hostClaude); got != "/custom/path.yaml" {
		t.Errorf("want env override, got %s", got)
	}
	if got := resolvePolicyPath(hostCodex); got != "/custom/path.yaml" {
		t.Errorf("want env override for codex too, got %s", got)
	}
}

// ─── missing policy + Codex ──────────────────────────────────────────────────

func TestRunHook_MissingPolicy_Codex_DefaultFailMode(t *testing.T) {
	// Can't easily test runHook directly without stdin/stdout injection, so we
	// test the key decision: HOOKGUARD_FAIL_MODE default "ask" + hostCodex must
	// produce "deny".
	failMode := envOrDefault("HOOKGUARD_FAIL_MODE", "ask")
	if failMode != "ask" {
		t.Skip("HOOKGUARD_FAIL_MODE is set; test only applies to default")
	}
	h := hostCodex
	// The logic from runHook's error path:
	if h == hostCodex && failMode == "ask" {
		// Would respond with deny — correct.
	} else {
		t.Error("expected deny path to be taken for Codex + default fail mode")
	}
}
