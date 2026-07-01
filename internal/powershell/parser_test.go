package powershell_test

import (
	"testing"

	"hookguard/internal/powershell"
)

func mustParse(t *testing.T, cmd string) *powershell.ParseResult {
	t.Helper()
	r, err := powershell.Parse(cmd)
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", cmd, err)
	}
	return r
}

func assertNotOpaque(t *testing.T, r *powershell.ParseResult) {
	t.Helper()
	if r.HasOpaqueExec {
		t.Errorf("expected not opaque, got reason: %s", r.OpaqueReason)
	}
}

func assertOpaque(t *testing.T, r *powershell.ParseResult) {
	t.Helper()
	if !r.HasOpaqueExec {
		t.Errorf("expected opaque execution, got segments: %+v", r.Segments)
	}
}

func hasSwitch(sw []string, name string) bool {
	for _, s := range sw {
		if s == name {
			return true
		}
	}
	return false
}

// ─── basic parsing ──────────────────────────────────────────────────────────

func TestParse_Empty(t *testing.T) {
	r := mustParse(t, "")
	assertNotOpaque(t, r)
	if len(r.Segments) != 0 {
		t.Errorf("expected 0 segments, got %d", len(r.Segments))
	}
}

func TestParse_SimpleCmdlet(t *testing.T) {
	r := mustParse(t, "Get-ChildItem -Path C:\\ -Recurse")
	assertNotOpaque(t, r)
	if len(r.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(r.Segments))
	}
	seg := r.Segments[0]
	if seg.Cmdlet != "Get-ChildItem" {
		t.Errorf("Cmdlet: want Get-ChildItem, got %s", seg.Cmdlet)
	}
	if seg.Parameters["Path"] != "C:\\" {
		t.Errorf("Parameters[Path]: want C:\\, got %q", seg.Parameters["Path"])
	}
	if !hasSwitch(seg.Switches, "Recurse") {
		t.Errorf("Switches: want Recurse present, got %v", seg.Switches)
	}
}

// ─── alias resolution ───────────────────────────────────────────────────────

func TestParse_AliasResolution(t *testing.T) {
	r := mustParse(t, "ri -Recurse -Force C:\\temp")
	assertNotOpaque(t, r)
	if len(r.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(r.Segments))
	}
	if r.Segments[0].Cmdlet != "Remove-Item" {
		t.Errorf("Cmdlet: want Remove-Item (from alias ri), got %s", r.Segments[0].Cmdlet)
	}
}

func TestParse_PipeSplitsSegments(t *testing.T) {
	r := mustParse(t, "Get-ChildItem | Remove-Item -Force")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d: %+v", len(r.Segments), r.Segments)
	}
	if r.Segments[0].Cmdlet != "Get-ChildItem" || r.Segments[1].Cmdlet != "Remove-Item" {
		t.Errorf("unexpected cmdlets: %+v", r.Segments)
	}
}

func TestParse_SemicolonSplitsSegments(t *testing.T) {
	r := mustParse(t, "Get-Date; Remove-Item foo.txt")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(r.Segments))
	}
}

func TestParse_AndAndSplitsSegments(t *testing.T) {
	r := mustParse(t, "New-Item foo.txt && Remove-Item foo.txt")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(r.Segments))
	}
}

// ─── opaque constructs ──────────────────────────────────────────────────────

func TestParse_InvokeExpressionOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "Invoke-Expression $x"))
}

func TestParse_IexAliasOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "iex 'Remove-Item C:\\'"))
}

func TestParse_DotSourcingOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, ". .\\script.ps1"))
}

func TestParse_DynamicCallOperatorOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "& $cmd"))
}

func TestParse_LiteralCallOperatorNotOpaque(t *testing.T) {
	r := mustParse(t, "& git status")
	assertNotOpaque(t, r)
	if len(r.Segments) != 1 || r.Segments[0].Cmdlet != "git" {
		t.Errorf("expected git segment, got %+v", r.Segments)
	}
}

func TestParse_EncodedCommandOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "powershell -EncodedCommand SQBFAFgA"))
}

func TestParse_AddTypeOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "Add-Type -TypeDefinition 'public class Foo {}'"))
}

func TestParse_IfControlStructureOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "if ($x -eq 1) { Remove-Item C:\\ }"))
}

func TestParse_ForeachKeywordOpaque(t *testing.T) {
	assertOpaque(t, mustParse(t, "foreach ($x in $y) { Remove-Item $x }"))
}

// ─── recursion into $(...) and { } (ADR 0005 / Frage 3 & 9) ────────────────

func TestParse_SubexpressionRecursesNotOpaque(t *testing.T) {
	r := mustParse(t, `Write-Host "$(Get-Date)"`)
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments (Write-Host + Get-Date), got %d: %+v", len(r.Segments), r.Segments)
	}
}

func TestParse_SubexpressionWithOpaqueContentPropagates(t *testing.T) {
	assertOpaque(t, mustParse(t, `Write-Host "$(Invoke-Expression $x)"`))
}

func TestParse_ForeachObjectAliasRecursesNotOpaque(t *testing.T) {
	r := mustParse(t, "Get-ChildItem | Where-Object { $_.Length -gt 100 } | Remove-Item")
	assertNotOpaque(t, r)
	// Get-ChildItem, Where-Object itself, Remove-Item; the scriptblock body
	// ($_.Length -gt 100) contains no cmdlet call so contributes no segment.
	if len(r.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d: %+v", len(r.Segments), r.Segments)
	}
}

func TestParse_ForeachPipedAliasNotOpaque(t *testing.T) {
	r := mustParse(t, "Get-ChildItem | foreach { Remove-Item $_ }")
	assertNotOpaque(t, r)
	// Get-ChildItem, the ForEach-Object alias itself, and the nested
	// Remove-Item inside its script block.
	if len(r.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d: %+v", len(r.Segments), r.Segments)
	}
	if r.Segments[2].Cmdlet != "Remove-Item" {
		t.Errorf("expected nested Remove-Item, got %+v", r.Segments[2])
	}
}

// ─── assignment stripping ───────────────────────────────────────────────────

func TestParse_AssignmentStripped(t *testing.T) {
	r := mustParse(t, "$results = Get-ChildItem -Recurse")
	assertNotOpaque(t, r)
	if len(r.Segments) != 1 || r.Segments[0].Cmdlet != "Get-ChildItem" {
		t.Errorf("expected Get-ChildItem segment, got %+v", r.Segments)
	}
}
