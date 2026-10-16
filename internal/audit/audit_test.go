package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afry23/hookguard/internal/audit"
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

func TestTruncateInput_CutsLongStringsRecursively(t *testing.T) {
	long := strings.Repeat("x", 1000)
	in := map[string]any{
		"short":  "ok",
		"long":   long,
		"n":      float64(3),
		"nested": map[string]any{"deep": long},
		"list":   []any{long, "ok"},
	}
	got := audit.TruncateInput(in)

	if got["short"] != "ok" || got["n"] != float64(3) {
		t.Errorf("short values must pass through: %v", got)
	}
	for name, v := range map[string]any{
		"long":   got["long"],
		"nested": got["nested"].(map[string]any)["deep"],
		"list":   got["list"].([]any)[0],
	} {
		s := v.(string)
		if len([]rune(s)) > 300 || !strings.HasSuffix(s, "(truncated)") {
			t.Errorf("%s not truncated: len=%d", name, len(s))
		}
	}
	if in["long"] != long {
		t.Error("input map must not be modified")
	}
}

func TestWrite_ToolInput_OmittedWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := audit.Write(path, audit.Entry{ToolName: "Read", Action: "allow"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "tool_input") {
		t.Errorf("tool_input must be omitted when unset: %s", data)
	}
}
