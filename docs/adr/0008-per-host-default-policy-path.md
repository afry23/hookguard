# Codex host defaults to its own policy file path

`hookguard claude` defaults to `~/.claude/hookguard.yaml` when
`HOOKGUARD_POLICY` isn't set. For `hookguard codex`, we default to a
separate `~/.codex/hookguard.yaml` instead of reusing the same path. This
mirrors where each host's own configuration already lives, at the cost that
a developer running both hosts must explicitly point them at a shared file
(via `HOOKGUARD_POLICY`) or symlink the two paths to keep policies in sync —
they will not converge by default.

## Considered Options

- Default both hosts to `~/.claude/hookguard.yaml` — rejected in favor of
  per-host convention; `HOOKGUARD_POLICY` remains available for users who
  want one shared file across hosts.
