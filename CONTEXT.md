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

## Example dialogue

> **Dev:** "Wenn ich eine Regel für `git push --force` schreibe, ist das ein
> Segment-Match oder ein When-Expression?"
> **Domain expert:** "Ein Sugar-Field-Match — `tool: git`, `subcommand:
> push`, `deny_flags: [--force]` kompiliert intern zu genau der
> When-Expression, die du sonst von Hand schreiben müsstest."
>
> **Dev:** "Und wenn zwei Regeln beide matchen, eine sagt allow, eine deny?"
> **Domain expert:** "Severity entscheidet, nicht die Reihenfolge — deny
> gewinnt immer, unabhängig davon, wo die Regel in der Liste steht."

## Flagged ambiguities

- "Policy" was used for both the whole `hookguard.yaml` file and a single entry
  in it — resolved: the whole file is the **Policy**, a single entry in its
  `rules:` list is a **Rule**.
