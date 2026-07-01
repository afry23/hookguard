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
`

func TestDecide_PowerShellRuleMatch(t *testing.T) {
	pol := loadTestPolicy(t, testYAML)
	input := hookInput{
		ToolName:  "PowerShell",
		ToolInput: map[string]any{"command": "Remove-Item -Recurse -Force C:\\"},
	}
	action, _ := decide(input, pol)
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
	action, reason := decide(input, pol)
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
	action, _ := decide(input, pol)
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
	action, reason := decide(input, pol)
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
	action, reason := decide(input, pol)
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
	action, _ := decide(input, pol)
	if action != policy.ActionDeny {
		t.Errorf("want default_action (deny) for unmatched tool, got %s", action)
	}
}
