package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"ctool-gate/internal/policy"
	"ctool-gate/internal/shell"
)

// ─── shared test policy ──────────────────────────────────────────────────────

const testPolicyYAML = `
version: 1
default_action: deny
audit_log: ""

flag_aliases:
  git:
    push:
      "-f": "--force"
    commit:
      "-n": "--no-verify"

opaque_execution_guard:
  action: ask

tools:
  git:
    default_action: allow
    subcommands:
      push:
        deny_flags:
          - "--force"
          - "--force-with-lease"
      commit:
        deny_flags:
          - "--no-verify"
      config:
        action: ask
        deny_args_regex:
          - "core\\.hooksPath"
          - "--global"
      tag:
        deny_flags:
          - "--delete"
          - "-d"
      "*":
        action: allow

  rm:
    default_action: ask

  curl:
    default_action: ask

  docker:
    default_action: ask
    subcommands:
      run:
        deny_flags:
          - "--privileged"
      ps:
        action: allow
      images:
        action: allow

  npm:
    default_action: allow
    subcommands:
      publish:
        action: ask
      install:
        action: allow
`

func loadTestPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "gate.yaml")
	if err := os.WriteFile(tmp, []byte(testPolicyYAML), 0o644); err != nil {
		t.Fatalf("write test policy: %v", err)
	}
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load test policy: %v", err)
	}
	return p
}

func seg(tool, sub string, flags, args []string) shell.Segment {
	return shell.Segment{Tool: tool, Subcommand: sub, Flags: flags, Args: args}
}

// ─── git push ────────────────────────────────────────────────────────────────

func TestGitPushForce_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "push", []string{"--force"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushForceWithLease_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "push", []string{"--force-with-lease"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushShortForceAlias_Denied(t *testing.T) {
	// -f must be normalised to --force via flag_aliases
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "push", []string{"-f"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for -f (alias → --force), got %s: %s", r.Action, r.Reason)
	}
}

func TestGitPushNormal_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "push", nil, []string{"origin", "main"}))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for normal push, got %s: %s", r.Action, r.Reason)
	}
}

// ─── git commit ──────────────────────────────────────────────────────────────

func TestGitCommitNoVerify_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "commit", []string{"--no-verify", "-m"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitCommitNoVerifyShortAlias_Denied(t *testing.T) {
	// -n must be normalised to --no-verify via flag_aliases
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "commit", []string{"-n"}, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for -n (alias → --no-verify), got %s: %s", r.Action, r.Reason)
	}
}

func TestGitCommitNormal_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "commit", []string{"-m"}, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for normal commit, got %s: %s", r.Action, r.Reason)
	}
}

// ─── git config ──────────────────────────────────────────────────────────────

func TestGitConfigHooksPath_Denied(t *testing.T) {
	// Attempting to override core.hooksPath is a common hook-bypass technique.
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "config", nil, []string{"core.hooksPath", "/dev/null"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for core.hooksPath, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitConfigGlobalFlag_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "config", nil, []string{"--global", "user.name", "test"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for --global arg, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitConfig_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "config", nil, []string{"user.email", "a@b.com"}))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for git config (no dangerous args), got %s: %s", r.Action, r.Reason)
	}
}

// ─── git wildcard ────────────────────────────────────────────────────────────

func TestGitStatus_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "status", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for git status, got %s: %s", r.Action, r.Reason)
	}
}

func TestGitLog_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("git", "log", []string{"--oneline"}, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for git log, got %s: %s", r.Action, r.Reason)
	}
}

// ─── rm ──────────────────────────────────────────────────────────────────────

func TestRm_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("rm", "", []string{"-r", "-f"}, []string{"/tmp/foo"}))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for rm, got %s: %s", r.Action, r.Reason)
	}
}

// ─── docker ──────────────────────────────────────────────────────────────────

func TestDockerRunPrivileged_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("docker", "run", []string{"--privileged"}, []string{"ubuntu"}))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for --privileged, got %s: %s", r.Action, r.Reason)
	}
}

func TestDockerPs_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("docker", "ps", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for docker ps, got %s: %s", r.Action, r.Reason)
	}
}

// ─── npm ─────────────────────────────────────────────────────────────────────

func TestNpmPublish_Ask(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("npm", "publish", nil, nil))
	if r.Action != policy.ActionAsk {
		t.Errorf("want ask for npm publish, got %s: %s", r.Action, r.Reason)
	}
}

func TestNpmInstall_Allowed(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("npm", "install", nil, nil))
	if r.Action != policy.ActionAllow {
		t.Errorf("want allow for npm install, got %s: %s", r.Action, r.Reason)
	}
}

// ─── unknown / default ───────────────────────────────────────────────────────

func TestUnknownTool_Denied(t *testing.T) {
	p := loadTestPolicy(t)
	r := p.Evaluate(seg("unknown-binary", "", nil, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("want deny for unknown tool (global default), got %s: %s", r.Action, r.Reason)
	}
}

// ─── Load edge cases ─────────────────────────────────────────────────────────

func TestLoad_MissingFile(t *testing.T) {
	_, err := policy.Load("/nonexistent/path/gate.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "gate.yaml")
	_ = os.WriteFile(tmp, []byte("{{: this is not valid yaml"), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoad_BadRegex(t *testing.T) {
	bad := `
tools:
  git:
    subcommands:
      config:
        deny_args_regex:
          - "[invalid regex"
`
	tmp := filepath.Join(t.TempDir(), "gate.yaml")
	_ = os.WriteFile(tmp, []byte(bad), 0o644)
	_, err := policy.Load(tmp)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestLoad_SecureDefaults(t *testing.T) {
	// An empty policy must still default to deny and ask for opaque.
	tmp := filepath.Join(t.TempDir(), "gate.yaml")
	_ = os.WriteFile(tmp, []byte("version: 1\n"), 0o644)
	p, err := policy.Load(tmp)
	if err != nil {
		t.Fatalf("load empty policy: %v", err)
	}
	r := p.Evaluate(seg("anything", "", nil, nil))
	if r.Action != policy.ActionDeny {
		t.Errorf("empty policy should default to deny, got %s", r.Action)
	}
	if p.OpaqueGuard.Action != policy.ActionAsk {
		t.Errorf("opaque guard should default to ask, got %s", p.OpaqueGuard.Action)
	}
}
