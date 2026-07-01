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
by splitting a command on pipes, `&&`, `;`, and similar boundaries. Only
Bash tool calls are broken into segments; other tools are matched directly
against their `tool_input`.
_Avoid_: Command, statement

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
distinct from both a **Rule** match and the **Default action**.
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
