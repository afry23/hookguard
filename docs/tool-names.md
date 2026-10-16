# Tool names in hookguard.yaml

hookguard has "tool" at three different levels in the schema. This doc lists
all three completely. For the rule syntax itself see
[configuration.md](configuration.md).

## 1. `tool_name` — top-level value from the hook payload

Every PreToolUse call (Claude Code or Codex) carries a `tool_name` field.
`tools:` (path sugar) matches directly against this value; `when:`
expressions read it as the `tool_name` variable.

| `tool_name` | Host | Meaning | How hookguard processes it |
|---|---|---|---|
| `Bash` | Claude Code, Codex (Linux/macOS) | Shell command | Split into segments (`\|`, `&&`, `;`, …); each segment checked against `tool:` sugar. Codex also reports Windows shell execution as `Bash`, but it's internally routed to the PowerShell path |
| `PowerShell` | Codex (Windows) | PowerShell command | Split into PowerShell segments; checked against `cmdlet:` sugar. Aliases (`rm`, `curl`, …) are resolved to the canonical cmdlet name first |
| `apply_patch` | Codex | Patch text (`*** Begin Patch` … `*** End Patch`) | Split into patch segments; each segment gets `EffectiveTool` = `Write` (new file) or `Edit` (update/delete/move) and is checked against `tools:`/`path` sugar as if it were a normal Edit/Write call |
| `Read` | Claude Code | Read a file | `tool_input.file_path` checked against `path:` sugar |
| `Edit` | Claude Code | Edit a file | `tool_input.file_path` checked against `path:` sugar |
| `Write` | Claude Code | Write/create a file | `tool_input.file_path` checked against `path:` sugar |
| `Glob` | Claude Code | File search by pattern | generic via `tools:`/`when` (no dedicated sugar field for `pattern`) |
| `Grep` | Claude Code | Content search | generic via `tools:`/`when` |
| `LS` | Claude Code | List a directory | generic via `tools:`/`when` |
| `WebFetch` | Claude Code | Fetch a URL | generic via `tools:`/`when` |
| `WebSearch` | Claude Code | Web search | generic via `tools:`/`when` |
| `mcp__<server>__<tool>` | Claude Code | MCP server tool | passed through to CEL as-is; match with `tools:` (wildcards allowed, e.g. `mcp__github__*`), constrain arguments with `input:` — see [MCP tools](configuration.md#mcp-tools) |
| *(any other)* | Claude Code (`Task`, `NotebookEdit`, …) | any tool without dedicated parsing | passed through to CEL as-is; matchable via `tools: ["<Name>"]` or `when: tool_name == "<Name>"`, `tool_input` stays a generic map |

No rule requires a known `tool_name` — any string works in `tools:`/`when`.
The list above only covers which names hookguard **specially** parses
(Bash/PowerShell segmentation, patch decomposition, `path` sugar).

`hookguard test` (testfile format) only supports the parsed names — see
[testing.md](testing.md); `apply_patch` is deliberately excluded there
(the multi-line patch format doesn't fit the one-line format).

---

## 2. `tool:` — Bash sugar field

`tool:` matches the **executable name** of a Bash segment (`segment.tool`).
The value is free-form — no enum, any program name works (`git`, `rm`,
`curl`, `docker`, `npm`, `go`, `python3`, `kubectl`, …). Only meaningful for
`tool_name == "Bash"`.

```yaml
- tool: git
  subcommand: push
  deny_flags: ["--force"]
  action: deny
```

Common examples from `config/hookguard.yaml`: `git`, `rm`, `curl`, `wget`,
`docker`, `npm`, `go`, `python`/`python3`, `pip`/`pip3`, `sh`, `bash`, plus
standard Unix tools (`ls`, `cat`, `grep`, `find`, `sed`, `awk`, `make`, …).

---

## 3. `cmdlet:` — PowerShell sugar field

`cmdlet:` matches the **canonical Verb-Noun cmdlet name**
(`ps_segment.cmdlet`). The value is free-form but must be the canonical
form — aliases are resolved before matching. Only meaningful for
`tool_name == "PowerShell"`.

```yaml
- cmdlet: Remove-Item
  action: ask
```

### Built-in alias table (alias → canonical cmdlet name)

| Alias(es) | Canonical name |
|---|---|
| `rm`, `ri`, `del`, `erase`, `rd`, `rmdir` | `Remove-Item` |
| `curl`, `iwr`, `wget` | `Invoke-WebRequest` |
| `iex` | `Invoke-Expression` (⚠ opaque — triggers the guard, see below) |
| `kill`, `spps` | `Stop-Process` |
| `gci`, `ls`, `dir` | `Get-ChildItem` |
| `cp`, `copy`, `cpi` | `Copy-Item` |
| `mv`, `move`, `mi` | `Move-Item` |
| `cat`, `type`, `gc` | `Get-Content` |
| `icm` | `Invoke-Command` |
| `saps`, `start` | `Start-Process` |
| `ii` | `Invoke-Item` |
| `%` | `ForEach-Object` |
| `where`, `?` | `Where-Object` |

A `cmdlet:` rule on `Remove-Item` therefore also matches `rm`, `ri`, `del`,
etc. automatically — the alias list isn't exhaustive (it covers common
cases); custom cmdlets/aliases outside the table need the canonical name
directly.

`Invoke-Expression` and `Add-Type` are considered **opaque** (dynamically
constructed code) and trigger `powershell_opaque_execution_guard` before
`cmdlet:` rules even run.

---

## 4. `tools:` — generic path/multi-tool sugar field

`tools:` is a list of arbitrary `tool_name` values (see the table in section
1 above). An entry containing a glob character (`*`, `?`, `[`, `{`) is matched
as a glob over the tool name, e.g. `mcp__github__*`; all other entries are
exact. Combined with `input:` it constrains individual `tool_input` keys (see
[MCP tools](configuration.md#mcp-tools)). Combined with `path:` it matches `tool_input.file_path` via glob —
useful for `Read`/`Edit`/`Write` (and `apply_patch` segments, which are
internally treated as `Edit`/`Write`). Without `path:` it matches every call
to the listed tools, regardless of payload content.

```yaml
- tools: ["Read"]
  path: "**/.env*"
  action: deny

- tools: ["Read", "Edit", "Write"]
  action: ask
```
