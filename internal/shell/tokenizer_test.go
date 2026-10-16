package shell_test

import (
	"testing"

	"github.com/afry23/hookguard/internal/shell"
)

// ─── helpers ────────────────────────────────────────────────────────────────

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func hasArg(args []string, arg string) bool {
	for _, a := range args {
		if a == arg {
			return true
		}
	}
	return false
}

func mustParse(t *testing.T, cmd string) *shell.ParseResult {
	t.Helper()
	r, err := shell.Parse(cmd)
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", cmd, err)
	}
	return r
}

func assertNotOpaque(t *testing.T, r *shell.ParseResult) {
	t.Helper()
	if r.HasOpaqueExec {
		t.Errorf("expected not opaque, got reason: %s", r.OpaqueReason)
	}
}

func assertOpaque(t *testing.T, r *shell.ParseResult) {
	t.Helper()
	if !r.HasOpaqueExec {
		t.Errorf("expected opaque execution, got segments: %+v", r.Segments)
	}
}

// ─── basic parsing ──────────────────────────────────────────────────────────

func TestParse_Empty(t *testing.T) {
	r := mustParse(t, "")
	assertNotOpaque(t, r)
	if len(r.Segments) != 0 {
		t.Errorf("expected 0 segments, got %d", len(r.Segments))
	}
}

func TestParse_SimpleGitPush(t *testing.T) {
	r := mustParse(t, "git push origin main")
	assertNotOpaque(t, r)
	if len(r.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(r.Segments))
	}
	seg := r.Segments[0]
	if seg.Tool != "git" {
		t.Errorf("Tool: want git, got %s", seg.Tool)
	}
	if seg.Subcommand != "push" {
		t.Errorf("Subcommand: want push, got %s", seg.Subcommand)
	}
	if len(seg.Flags) != 0 {
		t.Errorf("Flags: want none, got %v", seg.Flags)
	}
}

// ─── flag handling ──────────────────────────────────────────────────────────

func TestParse_LongFlag(t *testing.T) {
	r := mustParse(t, "git push --force origin main")
	assertNotOpaque(t, r)
	if !hasFlag(r.Segments[0].Flags, "--force") {
		t.Errorf("expected --force in flags, got %v", r.Segments[0].Flags)
	}
}

func TestParse_LongFlagWithEquals(t *testing.T) {
	r := mustParse(t, "git commit --message='initial commit'")
	assertNotOpaque(t, r)
	seg := r.Segments[0]
	if !hasFlag(seg.Flags, "--message") {
		t.Errorf("expected --message (stripped =value), got %v", seg.Flags)
	}
}

func TestParse_CombinedShortFlags(t *testing.T) {
	r := mustParse(t, "rm -rf /tmp/foo")
	assertNotOpaque(t, r)
	flags := r.Segments[0].Flags
	if !hasFlag(flags, "-r") {
		t.Errorf("expected -r after expansion, got %v", flags)
	}
	if !hasFlag(flags, "-f") {
		t.Errorf("expected -f after expansion, got %v", flags)
	}
	if hasFlag(flags, "-rf") {
		t.Errorf("-rf should have been expanded, but appears verbatim in %v", flags)
	}
}

func TestParse_CommitNoVerify(t *testing.T) {
	r := mustParse(t, "git commit --no-verify -m 'skip hooks'")
	assertNotOpaque(t, r)
	if !hasFlag(r.Segments[0].Flags, "--no-verify") {
		t.Errorf("expected --no-verify in flags, got %v", r.Segments[0].Flags)
	}
}

func TestParse_DoubleDashSeparator(t *testing.T) {
	// Arguments after -- must not be treated as flags.
	r := mustParse(t, "git log -- --all")
	assertNotOpaque(t, r)
	seg := r.Segments[0]
	if hasFlag(seg.Flags, "--all") {
		t.Errorf("--all after -- should be an arg, not a flag; flags=%v args=%v", seg.Flags, seg.Args)
	}
	if !hasArg(seg.Args, "--all") {
		t.Errorf("--all should be in args, got %v", seg.Args)
	}
}

// ─── compound commands ───────────────────────────────────────────────────────

func TestParse_AndAnd(t *testing.T) {
	r := mustParse(t, "git add . && git commit -m 'fix'")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d: %+v", len(r.Segments), r.Segments)
	}
	if r.Segments[0].Subcommand != "add" {
		t.Errorf("first segment subcommand: want add, got %s", r.Segments[0].Subcommand)
	}
	if r.Segments[1].Subcommand != "commit" {
		t.Errorf("second segment subcommand: want commit, got %s", r.Segments[1].Subcommand)
	}
}

func TestParse_Pipeline(t *testing.T) {
	r := mustParse(t, "git log --oneline | grep feat")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(r.Segments))
	}
	if r.Segments[0].Tool != "git" || r.Segments[1].Tool != "grep" {
		t.Errorf("unexpected tools: %v", r.Segments)
	}
}

func TestParse_Semicolon(t *testing.T) {
	r := mustParse(t, "cd /tmp; ls -la")
	assertNotOpaque(t, r)
	if len(r.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(r.Segments))
	}
}

// ─── opaque constructs ───────────────────────────────────────────────────────

func TestParse_OpaqueEval(t *testing.T) {
	assertOpaque(t, mustParse(t, "eval 'rm -rf /'"))
}

func TestParse_OpaqueCommandSubstitution(t *testing.T) {
	assertOpaque(t, mustParse(t, "git push $(get-remote)"))
}

func TestParse_OpaqueShDashC(t *testing.T) {
	assertOpaque(t, mustParse(t, `sh -c "rm -rf /"`))
}

func TestParse_OpaqueBashDashC(t *testing.T) {
	assertOpaque(t, mustParse(t, `bash -c 'git push --force'`))
}

func TestParse_OpaqueXargs(t *testing.T) {
	assertOpaque(t, mustParse(t, "cat cmds.txt | xargs git"))
}

func TestParse_OpaqueSource(t *testing.T) {
	assertOpaque(t, mustParse(t, "source /tmp/malicious.sh"))
}

func TestParse_OpaqueExec(t *testing.T) {
	assertOpaque(t, mustParse(t, "exec /tmp/bad"))
}

func TestParse_OpaqueEnvWrap(t *testing.T) {
	// env wrapping a command is opaque
	assertOpaque(t, mustParse(t, "env GIT_COMMITTER_DATE=2020-01-01 git commit --amend"))
}

func TestParse_OpaqueVariableInArg(t *testing.T) {
	assertOpaque(t, mustParse(t, "git push $REMOTE"))
}

// Subshells are not opaque: the parser walks into them, so every inner command
// still reaches policy evaluation as its own segment.
func TestParse_SubshellIsDecomposed(t *testing.T) {
	r := mustParse(t, "git push --force && (cd /tmp && rm -rf .)")
	assertNotOpaque(t, r)
	if len(r.Segments) != 3 {
		t.Fatalf("expected 3 segments, got %d: %+v", len(r.Segments), r.Segments)
	}
	for i, tool := range []string{"git", "cd", "rm"} {
		if r.Segments[i].Tool != tool {
			t.Errorf("segment %d: tool = %q, want %q", i, r.Segments[i].Tool, tool)
		}
	}
	if !hasFlag(r.Segments[2].Flags, "-r") || !hasFlag(r.Segments[2].Flags, "-f") {
		t.Errorf("rm segment lost its flags: %+v", r.Segments[2])
	}
}

// ─── sh without -c is NOT opaque ────────────────────────────────────────────

func TestParse_ShWithoutDashCIsNotOpaque(t *testing.T) {
	// Running "sh script.sh" (a named file) goes through normal policy.
	r := mustParse(t, "sh setup.sh")
	assertNotOpaque(t, r)
	if r.Segments[0].Tool != "sh" {
		t.Errorf("expected tool=sh, got %s", r.Segments[0].Tool)
	}
}
