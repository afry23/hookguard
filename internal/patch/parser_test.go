package patch_test

import (
	"testing"

	"github.com/afry23/hookguard/internal/patch"
)

func TestParse_SingleAdd(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: foo.go\n+package main\n*** End Patch"
	r, err := patch.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if r.HasOpaqueExec {
		t.Fatalf("unexpected opaque: %s", r.OpaqueReason)
	}
	if len(r.Segments) != 1 {
		t.Fatalf("want 1 segment, got %d", len(r.Segments))
	}
	s := r.Segments[0]
	if s.Op != patch.OpAdd || s.Path != "foo.go" || s.EffectiveTool != "Write" {
		t.Errorf("unexpected segment: %+v", s)
	}
}

func TestParse_SingleUpdate(t *testing.T) {
	text := "*** Begin Patch\n*** Update File: bar.go\n@@ -1,2 +1,2 @@\n-old\n+new\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 1 {
		t.Fatalf("got opaque or wrong count: %+v", r)
	}
	s := r.Segments[0]
	if s.Op != patch.OpUpdate || s.Path != "bar.go" || s.EffectiveTool != "Edit" {
		t.Errorf("unexpected: %+v", s)
	}
}

func TestParse_SingleDelete(t *testing.T) {
	text := "*** Begin Patch\n*** Delete File: old.go\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 1 {
		t.Fatalf("%+v", r)
	}
	s := r.Segments[0]
	if s.Op != patch.OpDelete || s.Path != "old.go" || s.EffectiveTool != "Edit" {
		t.Errorf("unexpected: %+v", s)
	}
}

func TestParse_UpdateWithMove(t *testing.T) {
	text := "*** Begin Patch\n*** Update File: src.go\n*** Move to: dst.go\n@@ -1 +1 @@\n-x\n+y\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec {
		t.Fatalf("opaque: %s", r.OpaqueReason)
	}
	if len(r.Segments) != 2 {
		t.Fatalf("want 2 segments, got %d", len(r.Segments))
	}
	if r.Segments[0].Op != patch.OpMoveSource || r.Segments[0].Path != "src.go" || r.Segments[0].EffectiveTool != "Edit" {
		t.Errorf("source: %+v", r.Segments[0])
	}
	if r.Segments[1].Op != patch.OpMoveDest || r.Segments[1].Path != "dst.go" || r.Segments[1].EffectiveTool != "Write" {
		t.Errorf("dest: %+v", r.Segments[1])
	}
}

func TestParse_MultipleSections_OrderPreserved(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: a.go\n+a\n*** Update File: b.go\n@@ @@\n-x\n+y\n*** Delete File: c.go\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 3 {
		t.Fatalf("want 3 segments, no opaque: %+v", r)
	}
	wantOps := []patch.Op{patch.OpAdd, patch.OpUpdate, patch.OpDelete}
	for i, want := range wantOps {
		if r.Segments[i].Op != want {
			t.Errorf("[%d] want op %s got %s", i, want, r.Segments[i].Op)
		}
	}
}

func TestParse_SamePath_TwoSections(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: foo.go\n+x\n*** Update File: foo.go\n@@ @@\n-x\n+y\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 2 {
		t.Fatalf("same path in two sections should yield 2 independent segments: %+v", r)
	}
}

func TestParse_MissingBeginPatch(t *testing.T) {
	text := "*** Add File: foo.go\n+x\n*** End Patch"
	r, _ := patch.Parse(text)
	if !r.HasOpaqueExec {
		t.Error("want opaque for missing *** Begin Patch")
	}
}

func TestParse_MissingEndPatch(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: foo.go\n+x"
	r, _ := patch.Parse(text)
	if !r.HasOpaqueExec {
		t.Error("want opaque for missing *** End Patch")
	}
}

func TestParse_UnrecognizedHeader(t *testing.T) {
	text := "*** Begin Patch\n*** Rename File: foo.go\n*** End Patch"
	r, _ := patch.Parse(text)
	if !r.HasOpaqueExec {
		t.Error("want opaque for unrecognized *** header")
	}
}

func TestParse_EmptyPathInAdd(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: \n*** End Patch"
	r, _ := patch.Parse(text)
	if !r.HasOpaqueExec {
		t.Error("want opaque for empty path after *** Add File:")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	r, err := patch.Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if r.HasOpaqueExec || len(r.Segments) != 0 {
		t.Error("empty input must return empty ParseResult, not opaque")
	}
}

func TestParse_WhitespaceOnlyInput(t *testing.T) {
	r, _ := patch.Parse("   \n\t  ")
	if r.HasOpaqueExec {
		t.Error("whitespace-only input should not be opaque")
	}
}

func TestParse_HunkBodyAndEndOfFileSkipped(t *testing.T) {
	text := "*** Begin Patch\n*** Update File: foo.go\n@@ -1,3 +1,3 @@\n context\n-old\n+new\n*** End of File\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 1 {
		t.Fatalf("hunk body and *** End of File should be skipped: %+v", r)
	}
}

func TestParse_CRLFTolerance(t *testing.T) {
	text := "*** Begin Patch\r\n*** Add File: foo.go\r\n+x\r\n*** End Patch"
	r, _ := patch.Parse(text)
	if r.HasOpaqueExec || len(r.Segments) != 1 {
		t.Fatalf("CRLF line endings not tolerated: %+v", r)
	}
	if r.Segments[0].Path != "foo.go" {
		t.Errorf("unexpected path: %q", r.Segments[0].Path)
	}
}

func TestParse_ContentBeforeFirstHeader(t *testing.T) {
	text := "*** Begin Patch\nsome unexpected line\n*** Add File: foo.go\n+x\n*** End Patch"
	r, _ := patch.Parse(text)
	if !r.HasOpaqueExec {
		t.Error("want opaque for non-*** content before first section header")
	}
}
