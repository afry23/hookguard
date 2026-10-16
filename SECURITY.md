# Security Policy

hookguard decides whether an AI coding agent may run a tool call, so a bypass
of its policy evaluation is a security issue.

## Supported versions

Security fixes are made on the latest release and on `main`.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub:
<https://github.com/afry23/hookguard/security/advisories/new>

Helpful details:

- the hook payload (stdin JSON) and the policy that leads to the wrong decision
- the host (`claude` or `codex`) and the hookguard version
- the decision you expected and the one you got

You can expect an acknowledgement within a few days. Once a fix is available,
the issue is disclosed in a GitHub security advisory, with credit if you want
it.

## What counts as a vulnerability

Examples: a command, PowerShell expression or `apply_patch` payload that is
allowed although a rule or opaque execution guard should have matched it, or
input that crashes the hook in a way that turns a `deny` or `ask` into an
`allow`.

Not covered: weaknesses of a user-written policy, or constructs the
documentation lists as out of scope for static analysis.
