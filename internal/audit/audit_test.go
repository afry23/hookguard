package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"hookguard/internal/audit"
)

func TestWrite_RoundTrip_WithHost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	entry := audit.Entry{
		Host:      "codex",
		SessionID: "s1",
		ToolName:  "apply_patch",
		Action:    "deny",
		Reason:    "test",
	}
	if err := audit.Write(path, entry); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got["host"] != "codex" {
		t.Errorf("host field: want %q, got %v", "codex", got["host"])
	}
}

func TestWrite_Host_OmittedWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	entry := audit.Entry{
		SessionID: "s1",
		ToolName:  "Bash",
		Action:    "allow",
	}
	if err := audit.Write(path, entry); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, _ := os.ReadFile(path)
	var got map[string]any
	_ = json.Unmarshal(data, &got)

	if _, present := got["host"]; present {
		t.Errorf("host field should be omitted when empty, got %v", got["host"])
	}
}
