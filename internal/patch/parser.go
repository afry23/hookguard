// Package patch parses Codex apply_patch tool_input.command text into
// structured Patch-Segments for policy evaluation, mirroring the shape of
// internal/shell and internal/powershell.
package patch

import (
	"fmt"
	"strings"
)

// Op identifies the kind of file operation in a Patch-Segment.
type Op string

const (
	OpAdd        Op = "add"         // *** Add File: path → EffectiveTool "Write"
	OpUpdate     Op = "update"      // *** Update File: path → EffectiveTool "Edit"
	OpDelete     Op = "delete"      // *** Delete File: path → EffectiveTool "Edit"
	OpMoveSource Op = "move_source" // source side of *** Move to: → EffectiveTool "Edit"
	OpMoveDest   Op = "move_dest"   // destination side of *** Move to: → EffectiveTool "Write"
)

// Segment is one parsed file operation extracted from an apply_patch call's
// raw patch text.
type Segment struct {
	Op            Op
	Path          string
	EffectiveTool string // "Edit" or "Write" — what to evaluate this segment against
}

// ParseResult holds the parsed segments and an opaque execution marker,
// using the same field names as shell.ParseResult and powershell.ParseResult
// so main.go's three dispatch branches stay symmetric.
type ParseResult struct {
	Segments      []Segment
	HasOpaqueExec bool
	OpaqueReason  string
}

// Parse parses the raw patch text from an apply_patch tool_input.command.
// Returns an empty ParseResult (not opaque) for empty/whitespace-only input,
// mirroring shell.Parse's handling of empty commands.
func Parse(text string) (*ParseResult, error) {
	if strings.TrimSpace(text) == "" {
		return &ParseResult{}, nil
	}

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	beginIdx := -1
	endIdx := -1
	for i, line := range lines {
		if line == "*** Begin Patch" {
			beginIdx = i
		}
		if line == "*** End Patch" {
			endIdx = i
		}
	}
	if beginIdx == -1 || endIdx == -1 {
		return opaqueResult("missing *** Begin Patch/*** End Patch envelope"), nil
	}

	inner := lines[beginIdx+1 : endIdx]
	var segments []Segment
	seenHeader := false

	i := 0
	for i < len(inner) {
		line := inner[i]

		if !strings.HasPrefix(line, "*** ") {
			if !seenHeader {
				return opaqueResult("content before first section header"), nil
			}
			i++ // hunk body line (@@, +, -, context) — skip
			continue
		}

		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			path := strings.TrimPrefix(line, "*** Add File: ")
			if path == "" {
				return opaqueResult("empty path in *** Add File:"), nil
			}
			seenHeader = true
			segments = append(segments, Segment{Op: OpAdd, Path: path, EffectiveTool: "Write"})
			i++

		case strings.HasPrefix(line, "*** Delete File: "):
			path := strings.TrimPrefix(line, "*** Delete File: ")
			if path == "" {
				return opaqueResult("empty path in *** Delete File:"), nil
			}
			seenHeader = true
			segments = append(segments, Segment{Op: OpDelete, Path: path, EffectiveTool: "Edit"})
			i++

		case strings.HasPrefix(line, "*** Update File: "):
			path := strings.TrimPrefix(line, "*** Update File: ")
			if path == "" {
				return opaqueResult("empty path in *** Update File:"), nil
			}
			seenHeader = true
			i++
			if i < len(inner) && strings.HasPrefix(inner[i], "*** Move to: ") {
				destPath := strings.TrimPrefix(inner[i], "*** Move to: ")
				if destPath == "" {
					return opaqueResult("empty path in *** Move to:"), nil
				}
				segments = append(segments, Segment{Op: OpMoveSource, Path: path, EffectiveTool: "Edit"})
				segments = append(segments, Segment{Op: OpMoveDest, Path: destPath, EffectiveTool: "Write"})
				i++
			} else {
				segments = append(segments, Segment{Op: OpUpdate, Path: path, EffectiveTool: "Edit"})
			}

		case line == "*** End of File":
			i++ // recognized hunk-body marker — skip

		default:
			return opaqueResult(fmt.Sprintf("unrecognized patch header: %q", line)), nil
		}
	}

	return &ParseResult{Segments: segments}, nil
}

func opaqueResult(reason string) *ParseResult {
	return &ParseResult{HasOpaqueExec: true, OpaqueReason: reason}
}
