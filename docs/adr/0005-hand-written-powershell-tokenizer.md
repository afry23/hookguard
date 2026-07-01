---
status: accepted
---

# PowerShell gets a hand-written tokenizer, not a blanket ask

[[0001]] gave PowerShell calls a fixed `ask`/`deny` with no inspection, deferring
real parsing as a future enhancement. We're building that parsing now, which
supersedes [[0001]].

Unlike Bash, no maintained Go library parses PowerShell into a tokenizer or
AST — a web search turned up only process wrappers (`go-powershell`, `gosh`)
that host a `pwsh` session and pass command strings through, not parsers.
The only real PowerShell parser lives in C# inside the PowerShell/PowerShell
repo itself. We considered shelling out to a real `pwsh.exe` at parse time to
get its AST as JSON, but rejected it: hookguard's whole design is low
single-digit-millisecond startup with no interpreter warm-up, and a per-call
process spawn also makes the gate depend on a local PowerShell install being
present. We're writing a hand-rolled tokenizer instead, scoped to the
security-relevant subset of syntax (cmdlet calls, operators, known-dangerous
constructs), not full grammar fidelity — the same posture the existing Bash
segmenter takes toward constructs it can't safely decompose.

Several sub-decisions fell out of this:

- **Target grammar is PowerShell 7+ only.** Claude Code launches `pwsh` on
  Windows when available, and 7+ syntax (`&&`, `||`) is a superset of
  Windows PowerShell 5.1's. Misparsing 5.1-only edge cases is acceptable
  because unparseable/unclear input already falls back to opaque handling.
- **`$(...)` subexpressions and scriptblock arguments to `ForEach-Object`/
  `Where-Object` are not blanket-opaque**, unlike Bash's `$(...)` command
  substitution. In PowerShell these are ordinary, extremely common syntax
  (`Write-Host "$(Get-Date)"`, `Where-Object { $_.Length -gt 100 }`); treating
  every occurrence as opaque would make the policy unusable for normal
  scripts. Their contents are instead recursed into and evaluated segment by
  segment, same as top-level calls — only genuinely dynamic content inside
  them (e.g. a nested `Invoke-Expression`) triggers the opaque guard.
- **PowerShell gets its own opaque guard** (`powershell_opaque_action`),
  separate from Bash's `opaque_execution_guard`, because the two parsers are
  independent implementations with independent risk profiles — a fresh,
  hand-written parser without an external library backing it warrants being
  tunable (and tightened) independently of the mature `mvdan.cc/sh`-based
  Bash path.
- **`powershell_action` is removed outright**, not kept as a deprecated
  alias. Existing configs that still set it will fail to compile against the
  new schema rather than silently keep working with different semantics.
- **Segments are a distinct type, not reused.** PowerShell parameters
  routinely carry values (`-Uri http://...`), unlike Bash's mostly value-less
  flags, so the PowerShell equivalent (`PowerShell-Segment`, exposed to CEL
  as `ps_segment`) splits `Parameters` (name+value) from `Switches`
  (value-less), rather than forcing both languages through Bash's
  `Segment.Flags []string` shape. The `deny_flags` sugar field name is
  reused for cmdlet rules, checking both `Parameters` keys and `Switches` by
  name only (no value matching) — value-based checks go through `when:` CEL.
- **PowerShell-internal aliases are resolved** (`rm`/`ri` → `Remove-Item`)
  before matching, since otherwise a rule written against the canonical
  cmdlet name is trivially bypassed. This does *not* extend to cross-language
  aliasing — a Bash `tool: rm` rule does not automatically also match
  PowerShell's `Remove-Item`; that mapping is a lossy heuristic (flag
  semantics differ) left to whoever writes the PowerShell-specific rule.
