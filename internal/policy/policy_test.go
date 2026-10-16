package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afry23/hookguard/internal/policy"
	"github.com/afry23/hookguard/internal/powershell"
	"github.com/afry23/hookguard/internal/shell"
)

// ─── shared test policy ──────────────────────────────────────────────────────

const testPolicyYAML = `
version: 1
default_action: deny
audit_log: ""

opaque_execution_guard:
  action: ask

powershell_opaque_execution_guard:
  action: ask

rules:
  - tool: git
    action: allow

  - tool: git
    subcommand: push
    deny_flags: ["--force", "--force-with-lease", "-f"]
    action: deny

  - tool: git
    subcommand: commit
    deny_flags: ["--no-verify", "-n"]
    action: deny

  - tool: git
    subcommand: config
    action: ask

  - tool: git
    subcommand: config
    when: >
      segment.args.exists(a, a.matches("core\\.hooksPath")) ||
      segment.flags.exists(f, f == "--global")
    action: deny
    reason: "hook bypass attempt"

  - tool: git
    subcommand: tag
    deny_flags: ["--delete", "-d"]
    action: deny

  - tool: rm
    action: ask

  - tool: curl
    action: ask

  - tool: docker
    when: '!(segment.subcommand in ["ps", "images"])'
    action: ask

  - tool: docker
    subcommand: run
    deny_flags: ["--privileged"]
    action: deny

  - tool: docker
    subcommand: ps
    action: allow

  - tool: docker
    subcommand: images
    action: allow

  - tool: npm
    action: allow

  - tool: npm
    subcommand: publish
    action: ask

  - tools: ["Read"]
    path: "**/.env*"
    action: deny

  - tools: ["Edit", "Write"]
    path: "**/secrets/**"
    action: deny

  - tools: ["Read"]
    when: 'tool_input.file_path.matches("id_rsa$")'
    action: deny
    reason: "reading SSH private keys is not allowed"

  - cmdlet: Remove-Item
    action: ask

  - cmdlet: Stop-Process
    deny_flags: ["Force"]
    action: deny
`

func loadTestPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	if err := os.WriteFile(tmp, []byte(testPolicyYAML), 0o644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load test policy: %v", err)
	}
	return p
}

func seg(tool, sub string, flags, args []string) *shell.Segment {
	return &shell.Segment{Tool: tool, Subcommand: sub, Flags: flags, Args: args}
}

func evalBash(p *policy.Policy, s *shell.Segment) policy.EvalResult {
	return p.Evaluate(policy.Activation{ToolName: "Bash", Segment: s})
}

func psSeg(cmdlet string, params map[string]string, switches, args []string) *powershell.Segment {
	if params == nil {
		params = map[string]string{}
	}
	return &powershell.Segment{Cmdlet: cmdlet, Parameters: params, Switches: switches, Args: args}
}

func evalPS(p *policy.Policy, s *powershell.Segment) policy.EvalResult {
	return p.Evaluate(policy.Activation{ToolName: "PowerShell", PSSegment: s})
}

// ─── git push ────────────────────────────────────────────────────────────────

func TestGitPushForce_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "push", []string{"--force"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushForceWithLease_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "push", []string{"--force-with-lease"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushShortForce_Denied(t *testing.T) {
	// -f is listed alongside --force in deny_flags (flag_aliases removed).
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "push", []string{"-f"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for -f, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushNormal_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "push", nil, []string{"origin", "main"}))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for normal push, got %s: %s", r.Action, r.Reason)
	}
}

// ─── git commit ──────────────────────────────────────────────────────────────

func TestGitCommitNoVerify_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "commit", []string{"--no-verify", "-m"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitCommitNoVerifyShort_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "commit", []string{"-n"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for -n, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitCommitNormal_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "commit", []string{"-m"}, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for normal commit, got %s: %s", r.Action, r.Reason)
	}
}

// ─── git config ──────────────────────────────────────────────────────────────

func TestGitConfigHooksPath_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "config", nil, []string{"core.hooksPath", "/dev/null"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for core.hooksPath, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitConfigGlobalFlag_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "config", []string{"--global"}, []string{"user.name", "test"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for --global flag, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitConfig_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "config", nil, []string{"user.email", "a@b.com"}))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for git config (no dangerous args), got %s: %s", r.Action, r.Reason)
	}
}

// ─── git wildcard ────────────────────────────────────────────────────────────

func TestGitStatus_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "status", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for git status, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitLog_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "log", []string{"--oneline"}, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for git log, got %s: %s", r.Action, r.Reason)
	}
}

// ─── PowerShell cmdlets ──────────────────────────────────────────────────────

func TestCmdletRemoveItem_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalPS(p, psSeg("Remove-Item", nil, []string{"Recurse", "Force"}, []string{"C:\\temp"}))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for Remove-Item, got %s: %s", r.Action, r.Reason)
	}
}

func TestCmdletStopProcessForce_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalPS(p, psSeg("Stop-Process", nil, []string{"Force"}, []string{"notepad"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for Stop-Process -Force, got %s: %s", r.Action, r.Reason)
	}
}

func TestCmdletStopProcessNoForce_DefaultAction(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalPS(p, psSeg("Stop-Process", nil, nil, []string{"notepad"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want default_action (deny), got %s: %s", r.Action, r.Reason)
	}
}

func TestCmdletUnrelated_DefaultAction(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalPS(p, psSeg("Get-ChildItem", nil, nil, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want default_action (deny) for unmatched cmdlet, got %s: %s", r.Action, r.Reason)
	}
}

// ─── rm ──────────────────────────────────────────────────────────────────────

func TestRm_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("rm", "", []string{"-r", "-f"}, []string{"/tmp/foo"}))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for rm, got %s: %s", r.Action, r.Reason)
	}
}

// ─── docker ──────────────────────────────────────────────────────────────────

func TestDockerRunPrivileged_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("docker", "run", []string{"--privileged"}, []string{"ubuntu"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for --privileged, got %s: %s", r.Action, r.Reason)
	}
}

func TestDockerPs_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("docker", "ps", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for docker ps, got %s: %s", r.Action, r.Reason)
	}
}

// ─── npm ─────────────────────────────────────────────────────────────────────

func TestNpmPublish_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("npm", "publish", nil, nil))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for npm publish, got %s: %s", r.Action, r.Reason)
	}
}

func TestNpmInstall_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("npm", "install", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for npm install, got %s: %s", r.Action, r.Reason)
	}
}

// ─── unknown / default ───────────────────────────────────────────────────────

func TestUnknownTool_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := evalBash(p, seg("unknown-binary", "", nil, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for unknown tool (global default), got %s: %s", r.Action, r.Reason)
	}
}

// ─── path sugar ──────────────────────────────────────────────────────────────

func TestReadEnvFile_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(policy.Activation{
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": "/app/.env.local"},
	})
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for reading .env file, got %s: %s", r.Action, r.Reason)
	}
}

func TestEditSecretsFile_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(policy.Activation{
		ToolName:  "Edit",
		ToolInput: map[string]any{"file_path": "/app/secrets/api-key.txt"},
	})
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for editing secrets file, got %s: %s", r.Action, r.Reason)
	}
}

func TestWriteSecretsFile_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(policy.Activation{
		ToolName:  "Write",
		ToolInput: map[string]any{"file_path": "/app/secrets/nested/api-key.txt"},
	})
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for writing secrets file, got %s: %s", r.Action, r.Reason)
	}
}

func TestReadOtherPath_Default(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(policy.Activation{
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": "/app/main.go"},
	})
	if r.Action != policy.ActionDeny {
		t.Errorf("want default_action (deny) for unmatched path, got %s: %s", r.Action, r.Reason)
	}
}

// ─── raw when: ───────────────────────────────────────────────────────────────

func TestReadIdRsa_DeniedWithReason(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(policy.Activation{
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": "/home/user/.ssh/id_rsa"},
	})
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for id_rsa read, got %s: %s", r.Action, r.Reason)
	}
	if r.Reason != "reading SSH private keys is not allowed" {
		t.Errorf("want rule-specific reason, got %q", r.Reason)
	}
}

// ─── severity across rules ────────────────────────────────────────────────────

func TestSeverityWinsOverBroadAllow(t *testing.T) {
	// "tool: git, action: allow" matches, and the more specific
	// "push --force" deny rule also matches. Severity (not order) must
	// decide the outcome: deny wins.
	p := loadTestPolicy(t)
	r := evalBash(p, seg("git", "push", []string{"--force"}, []string{"origin", "main"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny (severity beats broad allow), got %s: %s", r.Action, r.Reason)
	}
}

// ─── CEL runtime error escalation ────────────────────────────────────────────

func TestCELRuntimeError_EscalatesToAsk(t *testing.T) {
	// tool_input.file_path is only present for Read/Edit/Write calls; evaluating
	// it against a Bash activation (whose tool_input is empty) triggers a
	// CEL runtime "no such key" error, which must escalate to ask rather than
	// be silently ignored.
	badYAML := `
version: 1
default_action: allow
rules:
  - when: 'tool_input.file_path == "/etc/passwd"'
    action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	if err := os.WriteFile(tmp, []byte(badYAML), 0o644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load test policy: %v", err)
	}

	r := p.Evaluate(policy.Activation{ToolName: "Bash", ToolInput: map[string]any{}})
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask on CEL runtime error, got %s: %s", r.Action, r.Reason)
	}
}

// ─── Load edge cases ─────────────────────────────────────────────────────────

func TestLoad_MissingFile(t *testing.T) {
	_, err := policy.Load("/nonexistent/path/hookguard.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte("{{: this is not valid yaml"), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoad_InvalidCEL(t *testing.T) {
	bad := `
rules:
  - when: 'tool_name ==='
    action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(bad), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for invalid CEL, got nil")
	}
}

func TestLoad_RuleWithNoCondition(t *testing.T) {
	bad := `
rules:
  - action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(bad), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for rule without any condition, got nil")
	}
}

func TestLoad_ToolAndToolsBothSet(t *testing.T) {
	bad := `
rules:
  - tool: git
    tools: ["Read"]
    action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(bad), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error when both tool and tools are set, got nil")
	}
}

func TestLoad_InvalidGlobPattern(t *testing.T) {
	bad := `
rules:
  - tools: ["Read"]
    path: "[invalid"
    action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(bad), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for invalid glob pattern, got nil")
	}
}

func TestLoad_SecureDefaults(t *testing.T) {
	// An empty policy must still default to deny and ask-on-opaque for Bash,
	// PowerShell, and patch.
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte("version: 1\n"), 0o644)
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load empty policy: %v", err)
	}
	r := evalBash(p, seg("anything", "", nil, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("empty policy should default to deny, got %s", r.Action)
	}
	if p.OpaqueGuard.Action != policy.ActionAsk {
		t.Errorf("opaque guard should default to ask, got %s", p.OpaqueGuard.Action)
	}
	if p.PowerShellOpaqueGuard.Action != policy.ActionAsk {
		t.Errorf("powershell_opaque_execution_guard should default to ask, got %s", p.PowerShellOpaqueGuard.Action)
	}
	if p.PatchOpaqueGuard.Action != policy.ActionAsk {
		t.Errorf("patch_opaque_execution_guard should default to ask, got %s", p.PatchOpaqueGuard.Action)
	}
}

// ─── PatchOpaqueGuard ────────────────────────────────────────────────────────

func TestLoad_PatchOpaqueGuard_ExplicitDeny(t *testing.T) {
	yaml := `
version: 1
patch_opaque_execution_guard:
  action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(yaml), 0o644)
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.PatchOpaqueGuard.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s", p.PatchOpaqueGuard.Action)
	}
}

// ─── Codex-only CEL variables ─────────────────────────────────────────────────

func TestEvaluate_CodexVar_PermissionMode(t *testing.T) {
	yaml := `
version: 1
default_action: allow
rules:
  - when: 'permission_mode == "auto"'
    action: ask
    reason: "auto mode"
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(yaml), 0o644)
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	r := p.Evaluate(policy.Activation{
		ToolName:       "Bash",
		ToolInput:      map[string]any{},
		PermissionMode: "auto",
	})
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for permission_mode==auto, got %s", r.Action)
	}
}

func TestEvaluate_CodexVars_DefaultToEmptyString(t *testing.T) {
	// Codex-only vars default to "" when not set; rule must not cause a runtime
	// error and must fall through to default_action (allow).
	yaml := `
version: 1
default_action: allow
rules:
  - when: 'permission_mode == "auto"'
    action: deny
`
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	_ = os.WriteFile(tmp, []byte(yaml), 0o644)
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// No PermissionMode set → defaults to "" → rule does not match → allow.
	r := p.Evaluate(policy.Activation{
		ToolName:  "Bash",
		ToolInput: map[string]any{},
	})
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow when Codex vars are zero-value, got %s: %s", r.Action, r.Reason)
	}
}

// ─── MCP tools: wildcards, input sugar, on_error ─────────────────────────────

func loadYAML(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "hookguard.yaml")
	if err := os.WriteFile(tmp, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return p
}

func evalTool(p *policy.Policy, tool string, input map[string]any) policy.Action {
	return p.Evaluate(policy.Activation{ToolName: tool, ToolInput: input}).Action
}

const mcpPolicyYAML = `
version: 1
default_action: deny
rules:
  - tools: ["mcp__github__get_*", "mcp__github__list_*"]
    action: allow

  - tools: ["mcp__github__create_issue"]
    action: allow

  - tools: ["mcp__github__create_issue"]
    input:
      repo: ["secret-org/*", "archive/*"]
    action: deny
    reason: "no issues in protected orgs"

  - tools: ["mcp__fs__*"]
    input:
      path: "/etc/**"
    action: deny

  - tools: ["mcp__db__query"]
    input:
      limit: "0"
    action: ask
`

func TestToolsWildcard_MatchesPrefix(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	for _, tool := range []string{"mcp__github__get_issue", "mcp__github__list_prs"} {
		if got := evalTool(p, tool, map[string]any{}); got != policy.ActionAllow {
			t.Errorf("%s: want allow, got %s", tool, got)
		}
	}
}

func TestToolsWildcard_DoesNotMatchOtherTools(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	if got := evalTool(p, "mcp__github__delete_repo", map[string]any{}); got != policy.ActionDeny {
		t.Errorf("want default deny, got %s", got)
	}
}

func TestInput_MatchingValueTriggersRule(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	r := p.Evaluate(policy.Activation{
		ToolName:  "mcp__github__create_issue",
		ToolInput: map[string]any{"repo": "secret-org/app", "title": "x"},
	})
	if r.Action != policy.ActionDeny || r.Reason != "no issues in protected orgs" {
		t.Errorf("want deny with reason, got %s: %s", r.Action, r.Reason)
	}
}

func TestInput_OtherValueDoesNotTriggerRule(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	got := evalTool(p, "mcp__github__create_issue", map[string]any{"repo": "afry23/hookguard"})
	if got != policy.ActionAllow {
		t.Errorf("want allow, got %s", got)
	}
}

func TestInput_MissingKeyIsNotAnError(t *testing.T) {
	// The input rule must simply not apply when the key is absent, rather than
	// escalating to ask like a raw when: expression would.
	p := loadYAML(t, mcpPolicyYAML)
	got := evalTool(p, "mcp__github__create_issue", map[string]any{"title": "no repo given"})
	if got != policy.ActionAllow {
		t.Errorf("want allow (input rule skipped), got %s", got)
	}
}

func TestInput_UnlistedKeysAreIgnored(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	got := evalTool(p, "mcp__fs__read", map[string]any{"path": "/etc/passwd", "encoding": "utf8", "extra": 1})
	if got != policy.ActionDeny {
		t.Errorf("want deny, got %s", got)
	}
}

func TestInput_NonStringValuesCompareAsStrings(t *testing.T) {
	p := loadYAML(t, mcpPolicyYAML)
	// JSON numbers decode to float64.
	if got := evalTool(p, "mcp__db__query", map[string]any{"limit": float64(0)}); got != policy.ActionAsk {
		t.Errorf("limit 0: want ask, got %s", got)
	}
	if got := evalTool(p, "mcp__db__query", map[string]any{"limit": float64(10)}); got != policy.ActionDeny {
		t.Errorf("limit 10: want default deny, got %s", got)
	}
}

func TestInput_ScalarOrListAccepted(t *testing.T) {
	// "path" is written as a scalar, "repo" as a list in mcpPolicyYAML; both load.
	loadYAML(t, mcpPolicyYAML)
}

func TestOnError_SkipIgnoresMissingKey(t *testing.T) {
	p := loadYAML(t, `
version: 1
default_action: allow
rules:
  - tools: ["mcp__x__run"]
    when: 'tool_input.cmd.startsWith("rm")'
    on_error: skip
    action: deny
`)
	if got := evalTool(p, "mcp__x__run", map[string]any{}); got != policy.ActionAllow {
		t.Errorf("missing key with on_error=skip: want allow, got %s", got)
	}
	if got := evalTool(p, "mcp__x__run", map[string]any{"cmd": "rm -rf /"}); got != policy.ActionDeny {
		t.Errorf("present key: want deny, got %s", got)
	}
}

func TestOnError_DefaultStillAsks(t *testing.T) {
	p := loadYAML(t, `
version: 1
default_action: allow
rules:
  - tools: ["mcp__x__run"]
    when: 'tool_input.cmd.startsWith("rm")'
    action: deny
`)
	if got := evalTool(p, "mcp__x__run", map[string]any{}); got != policy.ActionAsk {
		t.Errorf("want ask on runtime error by default, got %s", got)
	}
}

func TestOnError_SkipDoesNotHideOtherDeny(t *testing.T) {
	p := loadYAML(t, `
version: 1
default_action: allow
rules:
  - tools: ["mcp__x__run"]
    when: 'tool_input.cmd.startsWith("rm")'
    on_error: skip
    action: deny
  - tools: ["mcp__x__*"]
    action: deny
`)
	if got := evalTool(p, "mcp__x__run", map[string]any{}); got != policy.ActionDeny {
		t.Errorf("want deny from second rule, got %s", got)
	}
}

func TestLoad_InvalidSugarCombinations(t *testing.T) {
	cases := map[string]string{
		"input without tools": `
  - when: "true"
    input: {a: "b"}
    action: deny`,
		"bad on_error": `
  - tools: ["x"]
    on_error: ignore
    action: deny`,
		"bad tools glob": `
  - tools: ["mcp__[x"]
    action: deny`,
		"bad input glob": `
  - tools: ["x"]
    input: {a: "[b"}
    action: deny`,
		"input not scalar or list": `
  - tools: ["x"]
    input: {a: {b: c}}
    action: deny`,
	}
	for name, rule := range cases {
		tmp := filepath.Join(t.TempDir(), "p.yaml")
		_ = os.WriteFile(tmp, []byte("version: 1\nrules:"+rule+"\n"), 0o644)
		if _, err := policy.Load(tmp); err == nil {
			t.Errorf("%s: want load error, got nil", name)
		}
	}
}

func TestInput_BoolNullAndNonScalar(t *testing.T) {
	p := loadYAML(t, `
version: 1
default_action: allow
rules:
  - tools: ["mcp__x__run"]
    input:
      force: "true"
    action: deny
`)
	if got := evalTool(p, "mcp__x__run", map[string]any{"force": true}); got != policy.ActionDeny {
		t.Errorf("bool true: want deny, got %s", got)
	}
	if got := evalTool(p, "mcp__x__run", map[string]any{"force": false}); got != policy.ActionAllow {
		t.Errorf("bool false: want allow, got %s", got)
	}
	if got := evalTool(p, "mcp__x__run", map[string]any{"force": nil}); got != policy.ActionAllow {
		t.Errorf("null: want allow (never matches), got %s", got)
	}
	// A nested object cannot be globbed: error, so the call escalates to ask.
	if got := evalTool(p, "mcp__x__run", map[string]any{"force": map[string]any{"a": 1}}); got != policy.ActionAsk {
		t.Errorf("object: want ask, got %s", got)
	}
}
