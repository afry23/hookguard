# Codex ask decisions are downgraded to deny

Codex's `PreToolUse` hook protocol only supports `allow` and `deny`; `ask` is
"parsed but not supported yet." Since hookguard's policy engine can still
resolve a Rule to `ask` (Claude Code supports it natively), we need a
Codex-specific mapping. We chose to downgrade `ask` to `deny` (fail closed),
with the reason string noting the downgrade, rather than silently upgrading
it to `allow`. Silently allowing an `ask`-rated action would weaken a
policy's intent without the user ever noticing; over-blocking is the safer
failure mode for a security gate. We rejected rejecting such policies at load
time, since a policy author may reasonably want the same rule to `ask` under
Claude Code and `deny` under Codex without maintaining two policy files.

## Considered Options

- Map `ask` → `allow` (fail open) — rejected: silently weakens security
  policy for Codex users.
- Reject at config load time if a Rule could produce `ask` under Codex —
  rejected: forces policy duplication across hosts for no safety benefit.
