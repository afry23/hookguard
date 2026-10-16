# Contributing to hookguard

Thanks for your interest in hookguard. Bug reports, policy ideas and pull
requests are welcome.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Contributions are licensed under the [MIT License](LICENSE).

## Reporting bugs and requesting features

- Search the [existing issues](https://github.com/afry23/hookguard/issues)
  first.
- Use the issue templates. For bugs, include the hook input (the JSON on
  stdin), your policy file, the host (`claude` or `codex`) and the decision you
  expected versus the one you got. `hookguard test` files make good
  reproductions.
- **Security problems** do not belong in public issues. See
  [SECURITY.md](SECURITY.md).

## Development setup

Requires Go 1.23 or newer.

```bash
git clone https://github.com/afry23/hookguard
cd hookguard

make build    # builds ./hookguard
make test     # go test ./...
make lint     # requires golangci-lint
```

To try a change by hand, pipe a hook payload into the binary; the
[README](README.md#development) has examples.

## Making changes

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. Unrelated cleanups belong in a separate pull
   request.
3. Add or update tests. Parser and policy changes should come with a test that
   fails without the change.
4. Run `gofmt`, `go vet ./...` and `make test` before pushing. CI runs the same
   checks plus `golangci-lint`.
5. Update the documentation in `README.md` and `docs/` when behaviour or
   configuration changes.
6. Open a pull request and describe what changed and why.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat: ...`, `fix: ...`, `docs: ...`, `test: ...`, `chore: ...`.

## Design notes

hookguard is a security tool, so it errs on the side of caution:

- A command that cannot be analysed statically is *opaque* and goes through the
  opaque execution guard instead of being allowed silently.
- Changes that make evaluation more permissive need a clear justification and
  a test for the case that is now allowed.
- Domain terms (segment, rule, opaque execution guard, ...) are defined in
  [CONTEXT.md](CONTEXT.md). Major decisions are recorded as ADRs in
  [docs/adr](docs/adr). For a decision that changes an ADR, add a new ADR
  instead of editing history.
