# hookguard

A Claude Code `PreToolUse` security gate: every tool call (Bash commands,
file reads/writes, …) is evaluated against a declarative policy before
execution, and resolved to allow, deny, or ask.

## Language

**Rule**:
A single entry in the policy's `rules:` list; matches a tool call via sugar
fields or a `when:` CEL expression and resolves to an action if it matches.
_Avoid_: Policy entry, condition

**Segment**:
One parsed unit of a Bash command (tool, subcommand, flags, args), produced
by splitting a command on pipes, `&&`, `;`, and similar boundaries. Bash tool
calls are broken into **Segments**; PowerShell tool calls are broken into
the structurally distinct **PowerShell-Segment** instead (see below); other
tools are matched directly against their `tool_input`.
_Avoid_: Command, statement

**PowerShell-Segment**:
One parsed unit of a PowerShell command: a **Cmdlet** name (aliases resolved
to their canonical form, e.g. `ri` → `Remove-Item`) plus its **Parameters**,
**Switches**, and positional arguments. The PowerShell analogue of a
**Segment**, but a distinct type — PowerShell parameters commonly carry
values (`-Uri http://...`), unlike Bash's mostly value-less flags — exposed
to CEL rules as `ps_segment` (vs. `segment` for Bash).
_Avoid_: Segment (reserved for Bash), command

**Cmdlet**:
The canonical Verb-Noun name of a PowerShell command (e.g. `Remove-Item`),
resolved from any built-in alias (`rm`, `ri`) before being matched against
policy rules.
_Avoid_: Command, function

**Parameter**:
A named PowerShell argument that takes a value (`-Uri http://...`), captured
on a **PowerShell-Segment**.
_Avoid_: Flag (Bash-specific term, see **Segment**)

**Switch**:
A named PowerShell argument with no value — a boolean flag (`-Force`,
`-Recurse`), captured on a **PowerShell-Segment**.
_Avoid_: Flag (Bash-specific term, see **Segment**)

**PowerShell opaque guard**:
The PowerShell-specific analogue of the **Opaque execution guard**: fires
when a PowerShell command cannot be safely parsed, or contains a construct
that cannot be safely decomposed into **PowerShell-Segments** (`Invoke-Expression`,
dot-sourcing, dynamic `&` call-operator targets, `-EncodedCommand`, dynamic
script-block construction, `Add-Type`, or `if`/`while`/`for`/`foreach`/`switch`
control structures). Configured and evaluated separately from the Bash
**Opaque execution guard**, since the two parsers are independent
implementations with independent risk profiles.
_Avoid_: Opaque execution guard (reserved for Bash), escape hatch

**Host**:
The agent CLI that issued a tool call and invoked hookguard as its hook —
`claude` or `codex`. Determined by which hookguard subcommand was invoked
(`hookguard claude` vs `hookguard codex`), not by sniffing the request body.
Governs host-specific behavior: the **Ask-to-deny downgrade**, which parser
handles a `Bash`-named call on Windows, and which Codex-only fields are
available to **When-expressions**.
_Avoid_: Client, agent, CLI

**Ask-to-deny downgrade**:
Codex has no `ask` channel (it can only `allow` or `deny` a tool call), so
when a **Rule** resolves to `ask` for a call from the Codex **Host**,
hookguard reports `deny` instead, with a reason noting the downgrade. Does
not apply to the Claude Code **Host**, which supports `ask` natively.
_Avoid_: Ask fallback, ask override

**Patch-Segment**:
One parsed file operation (Add File, Update File, Delete File, or Move To)
extracted from a Codex `apply_patch` call's raw patch text. The `apply_patch`
analogue of a **Segment** — an `apply_patch` call is decomposed into
Patch-Segments the same way a Bash command is decomposed into Segments, and
each is evaluated against path-based **Rules** independently, with the most
severe result across all of them winning. Update File and Delete File
Patch-Segments are evaluated as **Edit**; Add File and the destination side
of Move To are evaluated as **Write**; Move To also produces an Edit-shaped
Patch-Segment for its source path.
_Avoid_: Patch operation, file change

**Patch opaque guard**:
The `apply_patch` analogue of the **Opaque execution guard**: fires when a
Codex `apply_patch` call's raw patch text cannot be safely decomposed into
**Patch-Segments** (malformed patch, unrecognized format, ambiguous paths).
Configured and evaluated separately from the Bash and PowerShell opaque
guards.
_Avoid_: Opaque execution guard (reserved for Bash), PowerShell opaque guard
(reserved for PowerShell)

**Sugar field**:
A shorthand YAML field on a **Rule** (`tool`, `subcommand`, `deny_flags`,
`tools`, `path`) that compiles deterministically to an equivalent CEL
expression at load time, so common cases don't need hand-written CEL.
_Avoid_: Shortcut

**When-expression**:
The raw CEL boolean expression under a rule's `when:` field, used when sugar
fields aren't expressive enough (combined conditions, context access).
_Avoid_: Condition, predicate

**Severity**:
The ranking `deny(2) > ask(1) > allow(0)` used to resolve multiple matching
**Rules** for the same tool call — the most severe action wins, regardless
of the rules' order in the file.
_Avoid_: Priority — priority implies order-dependence, which this project
deliberately rejected (see ADR 0004)

**Test file**:
A plain-text file consumed by `hookguard test <file>`: one **Test case** per
non-comment, non-blank line (`Tool: Value -> decision`), validated as a whole
before any case runs — a malformed line aborts the run instead of letting
valid cases pass alongside a silently-skipped broken one.
_Avoid_: Test suite, fixture

**Test case**:
One parsed line of a **Test file** — a tool name, a value (mapped to the
matching `tool_input` field), and an expected **Action**. Evaluated through
the same `decide()` path as a real hook call for a given **Host**, and
reported as PASS or FAIL against the expected action.
_Avoid_: Assertion, expectation

**Default action**:
The top-level fallback action applied when *no* **Rule** in the list matches
a given tool call. A distinct mechanism from a **Rule** — it fires on the
absence of a match, not as a match itself.
_Avoid_: Fallback, catch-all rule

**Opaque execution guard**:
The preflight check that fires when a Bash command contains a construct that
cannot be safely decomposed into **Segments** (`eval`, `sh -c`, command
substitution, etc.). It short-circuits normal rule evaluation entirely,
distinct from both a **Rule** match and the **Default action**. Bash-specific;
see **PowerShell opaque guard** for the PowerShell analogue.
_Avoid_: Escape hatch, unsafe command

## Relationships

- A **Policy** (the loaded `hookguard.yaml`) contains an ordered list of **Rules**.
- A **Rule** is evaluated against exactly one tool call and yields at most
  one action if it matches; a **Rule**'s condition is either **Sugar
  fields** or a **When-expression** (or both).
- A **Segment** exists only for Bash tool calls; other tools (Read, Edit,
  Write) are matched directly against `tool_input` fields (e.g. `file_path`).
- **Severity** — not list order — decides which matching **Rule**'s action
  wins when several match the same call.
- The **Default action** applies only when zero **Rules** match; the
  **Opaque execution guard** applies *before* rule matching is attempted at
  all, for Bash calls that can't be split into **Segments** in the first
  place.
- A **PowerShell-Segment** is composed of one **Cmdlet** plus any number of
  **Parameters** and **Switches**; the **PowerShell opaque guard** applies
  *before* rule matching for PowerShell calls that can't be split into
  **PowerShell-Segments**, mirroring the **Opaque execution guard**'s role
  for Bash.
- Every tool call has exactly one **Host** (`claude` or `codex`), fixed for
  the whole hookguard invocation.
- An `apply_patch` call (Codex **Host** only) is decomposed into
  **Patch-Segments** the same way a Bash command is decomposed into
  **Segments**; the **Patch opaque guard** applies *before* rule matching for
  `apply_patch` calls that can't be split into **Patch-Segments**.
- The **Ask-to-deny downgrade** applies only to the Codex **Host**, after a
  **Rule**'s action has already been resolved to `ask` — it never affects the
  Claude Code **Host**.

## Example dialogue

> **Dev:** "If I write a rule for `git push --force`, is that a segment match
> or a when-expression?"
> **Domain expert:** "A sugar-field match — `tool: git`, `subcommand:
> push`, `deny_flags: [--force]` compiles internally to exactly the
> when-expression you'd otherwise have to write by hand."
>
> **Dev:** "And if two rules both match, one says allow, one says deny?"
> **Domain expert:** "Severity decides, not order — deny always wins,
> regardless of where the rule sits in the list."

## Flagged ambiguities

- "Policy" was used for both the whole `hookguard.yaml` file and a single entry
  in it — resolved: the whole file is the **Policy**, a single entry in its
  `rules:` list is a **Rule**.
