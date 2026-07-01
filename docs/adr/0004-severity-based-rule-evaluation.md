---
status: accepted
---

# Rule evaluation stays severity-based, not order-dependent

With the schema unified into a single `rules:` list ([[0003]]), we had to
decide how conflicting matches are resolved. Sudoers and iptables — both
referenced as inspiration for this project — use order-dependent evaluation
(last/first match wins), which enables an "exception to a general rule"
pattern but is also the classic sudoers footgun: a misplaced line silently
changes the meaning of the whole file.

We kept the existing severity-based model instead: every matching rule is
evaluated, and `deny > ask > allow` wins regardless of position in the file.
ctool-gate is a security gate, not a general-purpose rule engine with
intentional carve-outs, so a rule's restrictiveness should never depend on
where it happens to sit in the YAML — an overly broad `allow` can never
accidentally shadow a targeted `deny`. Genuine exceptions (e.g. "deny
`docker run --privileged` except for image X") are expressed as a single
CEL condition, not through file ordering.
