---
status: accepted
---

# CEL as the policy expression language

The pure-struct YAML schema (`deny_flags`, `deny_args_regex`) cannot express
combined conditions (AND/OR across flags and arguments), generic access to
each Claude Code tool's `tool_input` fields (Bash's `command` vs. Edit/Write's
`file_path` vs. others), or iteration over the pre-parsed Bash segments. We
considered three ways to add that expressiveness: OPA/Rego, a purpose-built
sudoers-style DSL, and CEL (`google/cel-go`).

We chose CEL. Rego is a full Datalog-style policy engine — more power than a
single-decision allow/deny/ask evaluation needs, and it carries a large
dependency tree that would meaningfully grow the binary. A custom DSL looks
simple to start but, once it has to support boolean combinators, generic
field access across heterogeneous schemas, and list iteration, becomes a
self-built expression parser/evaluator with all the edge cases, error
messages, and tests that implies. CEL is purpose-built for exactly this
"safely evaluate an expression over structured request data and return a
decision" problem — notably, Kubernetes' `ValidatingAdmissionPolicy` solves
the same shape of problem with CEL. It is non-Turing-complete (no runaway
policy expressions), a pure Go dependency (no CGO, moderate binary growth),
and provides `&&`/`||`/`in`, string functions, and list macros (`exists`,
`all`) out of the box.
