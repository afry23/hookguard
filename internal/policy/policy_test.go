package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"hookguard/internal/policy"
	"hookguard/internal/powershell"
	"hookguard/internal/shell"
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
	// An empty policy must still default to deny and ask-on-opaque for both
	// Bash and PowerShell.
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
}
