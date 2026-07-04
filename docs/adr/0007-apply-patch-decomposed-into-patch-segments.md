# apply_patch calls are decomposed into per-file Patch-Segments

Codex's `apply_patch` tool sends one call whose `tool_input.command` is raw
patch text that can touch multiple files with different operations (Add,
Update, Delete, Move) in a single invocation. To reuse existing path-based
Edit/Write Rules without requiring policy authors to write `apply_patch`
-specific rules, hookguard parses the patch text into per-file
Patch-Segments and evaluates each independently, resolving the call's final
action by severity across all of them — mirroring how a Bash pipeline is
split into Segments. Update and Delete operations are evaluated as Edit; Add
and the destination side of Move are evaluated as Write; Move also produces
an Edit-shaped Patch-Segment for its source path. An unparsable patch trips
the Patch opaque guard rather than falling through to the Default action.
We rejected evaluating the whole patch as one unit, since that would prevent
a Rule from denying just one sensitive file in an otherwise-fine multi-file
patch — the same reasoning that already justified per-Segment evaluation for
Bash and PowerShell.

## Considered Options

- Evaluate the whole `apply_patch` call as a single unit (e.g. against a
  combined path list) — rejected: can't isolate one sensitive path within a
  multi-file patch.
