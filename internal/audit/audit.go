// Package audit provides append-only JSONL structured logging for all tool
// call decisions made by hookguard.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Entry is one line in the audit log.
type Entry struct {
	// Timestamp is set automatically to UTC now if zero.
	Timestamp time.Time `json:"ts"`
	SessionID string    `json:"session_id,omitempty"`
	Cwd       string    `json:"cwd,omitempty"`
	// ToolName is the Claude Code tool invoked, e.g. "Bash", "Read", "Edit".
	ToolName string `json:"tool_name,omitempty"`
	// Command is the raw shell command string passed by Claude Code.
	// Only set for Bash tool calls.
	Command string `json:"cmd,omitempty"`
	// Action is the decision: "allow", "deny", or "ask".
	Action string `json:"action"`
	// Reason is the human-readable explanation for deny / ask decisions.
	Reason string `json:"reason,omitempty"`
}

// Write appends a JSON-encoded Entry (followed by a newline) to the file at
// path.  Parent directories are created if they do not exist.
//
// A leading "~/" in path is expanded to the current user's home directory.
//
// Concurrent safety: On Linux and macOS, writes appended to a file opened
// with O_APPEND are atomic for records smaller than PIPE_BUF (4 096 bytes),
// so simultaneous calls from independent hookguard processes (one per Claude
// Code session) are safe without additional locking.
func Write(path string, entry Entry) error {
	path = expandHome(path)

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(line)
	return err
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
