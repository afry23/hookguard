---
status: accepted
---

# Unified rules list with CEL, using sugar fields for the common case

With CEL chosen as the expression engine ([[0002]]), the policy schema still
needed a shape. We considered keeping today's `tools → subcommands` tree and
bolting CEL onto it via an optional `when:` field (with a separate top-level
section for path-based tools like Read/Edit/Write, which don't fit a
subcommand tree at all), versus replacing the tree entirely with one ordered
`rules:` list whose conditions are CEL, used uniformly across Bash segments
and file-path tools.

We chose full unification: a single `rules:` list is the only evaluation
model, covering Bash and Read/Edit/Write alike, instead of maintaining two
parallel mechanisms (a tree for Bash, a separate list for paths). Within that
list, rules are not required to be raw CEL — sugar fields (`tool`,
`subcommand`, `deny_flags`) are allowed and compile deterministically to the
equivalent CEL expression at load time, so the common case (deny a flag on a
git subcommand) stays as terse as it is today. `when:` remains available for
anything the sugar fields can't express. This is a breaking change to the
`gate.yaml` format — existing tree-based policy files will need to be
migrated, not just extended.
