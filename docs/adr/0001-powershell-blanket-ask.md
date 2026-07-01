---
status: superseded by ADR-0005
---

# PowerShell tool calls get a blanket ask, not real parsing

Claude Code's `PreToolUse` hook has so far only been registered for the `Bash`
matcher. On Windows, Claude Code also exposes a separate `PowerShell` tool
with its own syntax (cmdlets, `-Flag` semantics, different control operators)
that the existing `mvdan.cc/sh` tokenizer cannot parse — leaving PowerShell as
an unregulated bypass of the gate ("just use PowerShell instead of Bash").

We decided to register the hook for `matcher: "PowerShell"` as well, but
without a dedicated PowerShell tokenizer/segmenter: every PowerShell call is
given a fixed `ask` (configurable to `deny`) decision, with no inspection of
the command content. This closes the bypass immediately without taking on
the cost of a full PowerShell parser before the policy DSL work is scoped. A
real PowerShell-aware tokenizer is deferred as a future, explicit
enhancement.
