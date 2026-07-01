# ctool-gate → hookguard: Umbenennung + Policy-Schema-Redesign auf CEL-basierte Rules-Liste

## Umbenennung (zusätzlich zum CEL-Redesign, in einem Zug)

Das Tool wird im selben Schritt von `ctool-gate` zu `hookguard` umbenannt (Nutzerentscheidung: zusammen mit dem CEL-Redesign, da ohnehin fast jede Datei angefasst wird; volle Reichweite: Modul, Binary, ENV-Vars, Doku; Config-Datei wird zu `hookguard.yaml`). Betrifft:

- **`go.mod`**: `module ctool-gate` → `module hookguard`. Alle internen Imports (`"ctool-gate/internal/policy"`, `"ctool-gate/internal/shell"`, `"ctool-gate/internal/audit"`) ändern sich entsprechend auf `"hookguard/internal/..."`.
- **Verzeichnis**: `cmd/ctool-gate/` → `cmd/hookguard/` (inkl. `main.go` → bleibt `main.go`, nur der Ordner wandert).
- **Binary-/Install-Name**: Makefile (`go build -o ctool-gate` → `-o hookguard`, `install`-Target entsprechend).
- **ENV-Vars**: `CTOOL_GATE_POLICY` → `HOOKGUARD_POLICY`, `CTOOL_GATE_FAIL_MODE` → `HOOKGUARD_FAIL_MODE`.
- **Default-Policy-Pfad**: `~/.claude/gate.yaml` → `~/.claude/hookguard.yaml` (in `resolvePolicyPath()` in `main.go`).
- **Config-Datei**: `config/gate.yaml` → `config/hookguard.yaml`.
- **Doku**: `README.md` (Titel, alle Beispiele/Pfade/ENV-Var-Namen), `CONTEXT.md` (Titel „ctool-gate" → „hookguard"), ADRs 0001–0004 bleiben inhaltlich unverändert (sie beschreiben Entscheidungen, keinen Tool-Namen direkt), aber ein kurzer Hinweis/Nachtrag ist nicht nötig, da sie den Tool-Namen nicht im Fließtext verwenden — nur bei Bedarf prüfen.
- Git-Hook-Beispiel in der README (`.git/hooks/pre-push`) und Settings.json-Snippets (`"command": "ctool-gate"`) entsprechend anpassen.

## Context

`ctool-gate` ist ein Claude Code `PreToolUse`-Hook, der bisher nur Bash-Kommandos gegen eine starre `tools → subcommands`-YAML-Baumstruktur prüft (`deny_flags`, `deny_args_regex`). Diese Struktur kann keine kombinierten Bedingungen (UND/ODER), keinen generischen Zugriff auf beliebige `tool_input`-Felder anderer Tools (Read/Edit/Write) und keine Pfad-Regeln ausdrücken.

In einer vorangegangenen Grill-Session (siehe `CONTEXT.md` und `docs/adr/0001`–`0004` im Repo) wurde entschieden:
- **CEL** (`google/cel-go`) wird die Ausdruckssprache (ADR 0002), nicht Rego oder eine eigene DSL.
- Das Schema wird zu einer **einzigen `rules:`-Liste vereinheitlicht** (ADR 0003), die sowohl Bash-Segmente als auch Read/Edit/Write-Pfadzugriffe abdeckt. Einfache Fälle nutzen **Sugar-Felder** (`tool`, `subcommand`, `deny_flags`, `tools`, `path`), die zu CEL kompilieren; komplexe Fälle nutzen rohes `when:`.
- Mehrere zutreffende Regeln werden **severity-basiert** aufgelöst (`deny > ask > allow`), nicht nach Reihenfolge (ADR 0004).
- PowerShell-Aufrufe (Windows) bekommen vorerst pauschal eine konfigurierbare Aktion ohne Parsing (ADR 0001).
- `default_action` und `opaque_execution_guard` bleiben eigene Top-Level-Felder, kein Regel-Treffer im eigentlichen Sinn.
- Kein Migrationspfad nötig — das Tool hat noch keine Nutzer/Bestandskonfigurationen; reiner Breaking Change.

Dieser Plan setzt diese bereits getroffenen Entscheidungen technisch um. Zusätzlich wurden vier offene Implementierungsfragen mit dem Nutzer geklärt:
1. **`is_opaque`** wird **nicht** in die CEL-Umgebung aufgenommen (aktuell ohnehin immer `false`, da der Opaque-Guard die Regelauswertung komplett vor CEL abfängt — unnötige API-Fläche für v1).
2. Ein **CEL-Laufzeitfehler** in einer Regel eskaliert auf **`ask`** für diese Regel (nicht stillschweigend ignorieren) — die Regel nimmt dann mit Aktion `ask` an der normalen Severity-Auflösung teil, sodass ein anderswo zutreffendes `deny` weiterhin gewinnt, aber der Fehler nicht unbemerkt zu `allow` führen kann.
3. **`flag_aliases` entfällt ersatzlos** — `deny_flags` listet Kurz- und Langform einfach beide auf (z. B. `["-f", "--force"]`). Dokumentierter, bewusster Funktionsverlust.
4. **`glob(path, pattern)`** ist die Argumentreihenfolge der neuen CEL-Funktion für Pfad-Matching.

## Neue Typen und Kernlogik (`internal/policy/`)

Aufteilung in drei Dateien:
- `internal/policy/policy.go` — `Action`/`Severity` (unverändert), `Rule`, `Policy`, `Activation`, `EvalResult`, `Load`, `Evaluate`.
- `internal/policy/cel_env.go` — `newCELEnv() (*cel.Env, error)` inkl. der `glob`-Funktion.
- `internal/policy/sugar.go` — Sugar-zu-CEL-Kompilierung + Validierung pro Regel.

### CEL-Umgebung (`cel_env.go`)

Variablen, die jedem `when:`-Ausdruck und jeder Sugar-Kompilierung zur Verfügung stehen:

| Name | CEL-Typ | Quelle | Hinweis |
|---|---|---|---|
| `tool_name` | `string` | `hookInput.ToolName` | z. B. `"Bash"`, `"Read"` |
| `tool_input` | `dyn` (map) | dekodiertes `tool_input`-JSON-Objekt | generisch, z. B. `{"file_path": "..."}` |
| `segment` | `dyn` (map) | aktuelles `shell.Segment`, **nur Bash** | `{tool, subcommand, flags, args}`; bei Nicht-Bash-Aufrufen ein Zero-Value-Map (`tool:"", subcommand:"", flags:[], args:[]`), nie fehlend/null |
| `cwd` | `string` | `hookInput.Cwd` | |
| `session_id` | `string` | `hookInput.SessionID` | |

Custom-Funktion `glob(path string, pattern string) bool`, implementiert über `github.com/bmatcuk/doublestar/v4` (`doublestar.Match(pattern, path)` — Achtung: doublestar's eigene Signatur hat Pattern zuerst, also beim Binding die Argumente entsprechend vertauschen).

### Neue/geänderte Dependencies (`go.mod`)

```
go get github.com/google/cel-go@latest
go get github.com/bmatcuk/doublestar/v4@latest
go mod tidy
```
Reine Go-Module, kein CGO, kein Vendoring (Internetzugriff beim Build vorausgesetzt, wie heute schon).

### `Rule`-Typ (`policy.go`)

```go
type Rule struct {
    // Bash-Sugar (exklusiv zu Tools/Path)
    Tool       string   `yaml:"tool"`
    Subcommand string   `yaml:"subcommand"`
    DenyFlags  []string `yaml:"deny_flags"`

    // Pfad-Sugar (Read/Edit/Write)
    Tools []string `yaml:"tools"`
    Path  string   `yaml:"path"`

    // Rohes CEL, wird mit ggf. vorhandenem Sugar-Ausdruck UND-verknüpft
    When string `yaml:"when"`

    Action Action `yaml:"action"`
    Reason string `yaml:"reason"`

    // von Load() gesetzt, nicht aus YAML
    program    cel.Program
    scopeTools map[string]bool // nil = für jeden tool_name auswerten
}
```

`FlagAliases`, `ToolPolicy`, `SubcommandPolicy` werden komplett gelöscht.

`Policy` bekommt zusätzlich `PowerShellAction Action `yaml:"powershell_action"`` (Default `ask`, analog zu `OpaqueGuard`).

### `Load(path string) (*Policy, error)`

1. YAML einlesen wie heute.
2. Sichere Defaults: `DefaultAction` → `deny`, `OpaqueGuard.Action` → `ask`, **neu** `PowerShellAction` → `ask`.
3. `env, _ := newCELEnv()`.
4. Für jede `Rule`: Validierung + Kompilierung (siehe unten), Fehler sofort mit Regel-Index zurückgeben (`fmt.Errorf("rule %d: %w", i, err)`) — Kompilierfehler fallen beim Laden auf, nicht erst zur Laufzeit.

### Sugar-Kompilierung (`sugar.go`)

Validierung pro Regel:
- Fehler, wenn sowohl `Tool != ""` als auch `len(Tools) > 0` gesetzt sind.
- Fehler, wenn `Subcommand`/`DenyFlags` gesetzt sind, aber `Tool == ""`.
- Fehler, wenn `Path != ""`, aber `len(Tools) == 0`.
- Fehler, wenn eine Regel gar keine Bedingung hat (`Tool == "" && len(Tools) == 0 && When == ""`).
- Malformed Glob-Pattern in `Path`: mit `doublestar.Match(pattern, "")` (Dummy-Pfad) einmalig zur Ladezeit prüfen, damit auch das beim `Load()` auffällt statt erst zur Laufzeit.

CEL-Quellstring bauen (Sugar-Teile mit `&&` verbinden, `When` in Klammern anhängen falls vorhanden), dann `env.Compile(source)` + `env.Program(ast)`, Ergebnis in `r.program` cachen. `scopeTools` wird aus `Tool`/`Tools` abgeleitet (nur zur Performance-Optimierung — rohe `when:`-only-Regeln haben `scopeTools == nil` und werden immer ausgewertet).

Beispiel Bash-Sugar → CEL:
```
tool_name == "Bash" && segment.tool == "git" && segment.subcommand == "push"
  && segment.flags.exists(f, f in ["--force", "--force-with-lease", "-f"])
```
Beispiel Pfad-Sugar → CEL:
```
tool_name in ["Read"] && glob(tool_input.file_path, "**/.env*")
```

### `Evaluate(a Activation) EvalResult`

Iteriert über alle Regeln; überspringt eine Regel ohne CEL-Auswertung, wenn `scopeTools` gesetzt ist und `tool_name` nicht enthält (Performance). Für jede verbleibende Regel:
- CEL-Programm mit den Aktivierungs-Variablen auswerten.
- **Laufzeitfehler** (z. B. Feldzugriff schlägt fehl): Regel gilt als **getroffen mit Aktion `ask`** und einem generierten Reason-Text (`"rule %d: CEL evaluation error: %v"`) — nimmt so an der Severity-Auflösung teil, statt stillschweigend übersprungen zu werden (geklärte Nutzerentscheidung).
- Boolean `true`: Regel-Aktion und Reason gegen den bisher besten Severity-Wert vergleichen (`deny > ask > allow`), `bestSeverity` startet bei `-1`, damit jede getroffene Regel `default_action` schlägt.
- Kein Treffer insgesamt → `default_action` mit generiertem Reason.

`Activation` enthält `ToolName`, `ToolInput map[string]any`, `Cwd`, `SessionID`, `Segment *shell.Segment` (nil bei Nicht-Bash). Kein `IsOpaque`-Feld (geklärte Entscheidung).

Die Mehrsegment-Logik (mehrere Pipeline-Segmente in einem Bash-Kommando, severity-basiert kombiniert) bleibt in `main.go` — `Evaluate` wertet immer nur *eine* Activation aus, bleibt so klein und testbar.

## `cmd/hookguard/main.go` (neuer Pfad nach Umbenennung)

- `hookInput.ToolInput` wird zu `map[string]any` (statt festem `toolInput{Command string}`-Struct), damit beliebige `tool_input`-Felder für CEL zugänglich sind. Bash-Kommando wird per Typ-Assertion extrahiert: `cmdStr, _ := input.ToolInput["command"].(string)`.
- Neue, testbare Funktion `decide(input hookInput, pol *policy.Policy) (policy.Action, string)`, die die gesamte Entscheidungslogik kapselt:
  1. `tool_name == "PowerShell"` → sofort `pol.PowerShellAction` zurückgeben, kein Parsing (ADR 0001).
  2. `tool_name != "Bash"` → einmaliges `Evaluate` mit `Activation{ToolName, ToolInput, Cwd, SessionID}` (kein Segment).
  3. `tool_name == "Bash"` → wie heute: `shell.Parse`, bei `HasOpaqueExec` sofort `OpaqueGuard.Action`, sonst pro Segment `Evaluate` aufrufen und severity-basiert über alle Segmente kombinieren (bestehende Logik, nur über `Evaluate` statt der alten `Policy.Evaluate(seg)`-Signatur).
- `main()` schrumpft auf: Stdin dekodieren → Policy laden (Fail-Mode-Handling unverändert) → `decide(input, pol)` → Audit-Eintrag schreiben → `respond`.

## `internal/audit/audit.go`

Kleine additive Erweiterung: `Entry` bekommt `ToolName string `json:"tool_name,omitempty"``; `Command` wird `omitempty` (nur bei Bash gesetzt). `main.go` befüllt `ToolName` immer, `Command` nur für Bash. Macht Audit-Zeilen für Read/Edit/Write-Denials aussagekräftig.

## Config & Doku

- `config/gate.yaml` → **`config/hookguard.yaml`** (neuer Dateiname, siehe Umbenennungs-Abschnitt): vollständig neu schreiben mit `rules:`-Liste — alle vier Regel-Formen demonstrieren (Bash-Sugar für git/docker/npm/rm wie heute, Pfad-Sugar für `.env*`/`secrets/**`, ein `when:`-Beispiel z. B. `id_rsa`-Blockade), `powershell_action: ask` ergänzen, Header-Kommentar auf neues Schema und neuen Tool-Namen anpassen. `core.hooksPath`/`--global`- und Docker-Root-FS/Socket-Regeln werden zu `when:`-Regeln (Ersatz für das alte `deny_args_regex`).
- `README.md`: Titel/Beispiele auf „hookguard" umstellen, Architektur-Diagramm (CEL-Kompilierschritt erwähnen), vollständige Schema-Referenz für `rules:` (alle Sugar-Felder + `when:` + CEL-Variablentabelle + `glob()`-Signatur), `powershell_action`-Feld dokumentieren, neue ENV-Var-Namen (`HOOKGUARD_POLICY`/`HOOKGUARD_FAIL_MODE`) und neuer Default-Pfad (`~/.claude/hookguard.yaml`), Breaking-Change-Hinweis (kein Migrationspfad, alte Version ggf. per Git-Tag verfügbar), aktualisiertes Audit-Log-Beispiel, aktualisiertes Projektstruktur-Diagramm (neue Dateien `cel_env.go`/`sugar.go`, neuer Ordner `cmd/hookguard/`).
- `CONTEXT.md`: Titelzeile „ctool-gate" → „hookguard".

## Tests

**`internal/policy/policy_test.go`** — komplett neu, gleicher Stil wie heute (einzelne Testfunktionen, kein Table-Driven, `loadTestPolicy(t)`-Helper mit inline YAML-Fixture, kleine Helper wie `seg(...)`). Testfälle:
- Bash-Sugar: Force-Push-Deny (inkl. beider Flag-Formen `-f`/`--force` in `deny_flags`, als Ersatz für `flag_aliases`), Commit-No-Verify-Deny, Config-Ask + `when:`-Regel für `core.hooksPath`/`--global`, Docker-Privileged-Deny, Npm-Publish-Ask, unbekanntes Tool → `default_action`.
- Pfad-Sugar: `Read` auf `.env*` → deny, `Edit`/`Write` auf `secrets/**` → deny, anderer Pfad → `default_action`.
- Rohes `when:`: `id_rsa`-Read-Deny mit regelspezifischem `Reason`.
- Severity-über-Regeln: Ein Segment matched sowohl eine breite `tool: git, action: allow`-Regel als auch die spezifische `push --force`-Deny-Regel → Ergebnis muss `deny` sein (beweist Severity-, nicht Reihenfolge-Logik).
- CEL-Laufzeitfehler-Eskalation: eine Regel, deren `when:` bei bestimmten `tool_name`-Werten einen Feldzugriffsfehler wirft → Ergebnis `ask` (neue Testfunktion, deckt die geklärte Nutzerentscheidung ab).
- `Load()`-Validierung: ungültiges CEL, Regel ohne jede Bedingung, `tool`+`tools` gleichzeitig gesetzt, ungültiges Glob-Pattern (falls von doublestar zur Ladezeit erkennbar), fehlende Datei, ungültiges YAML, sichere Defaults inkl. `PowerShellAction`.

**`cmd/hookguard/main_test.go`** — neu (heute keine Tests vorhanden), testet `decide()` direkt ohne Stdin/Stdout:
- PowerShell → konfigurierte Aktion, unabhängig von jeder sonst zutreffenden Regel (beweist den Kurzschluss).
- Read/Edit/Write-Pfadregeln greifen End-to-End über `decide()`.
- Bash-Regressionstest (`git push --force` → deny) über den vollen Segment-Loop.
- Unbekanntes Nicht-Bash-Tool ohne passende Regel → `default_action`.

**Verifikation:** `go build ./...`, `go test -v -count=1 ./...` (bzw. `make test`), `make lint` falls golangci-lint verfügbar. Zusätzlich manueller End-to-End-Test wie in der README-„Development"-Sektion beschrieben: Beispiel-JSON für Bash, Read und PowerShell durch das gebaute `hookguard`-Binary pipen und die `permissionDecision`/`permissionDecisionReason`-Ausgabe gegen die neue `config/hookguard.yaml` prüfen.

## Reihenfolge der Umsetzung

1. Umbenennung: `go.mod` (`module hookguard`), Verzeichnis `cmd/ctool-gate/` → `cmd/hookguard/`, alle internen Imports auf `hookguard/internal/...` anpassen, Makefile-Binary-/Install-Name, ENV-Var-Namen und Default-Policy-Pfad in `main.go` (`resolvePolicyPath`).
2. `go.mod`: CEL/Glob-Dependencies hinzufügen, `go mod tidy`.
3. `internal/policy/cel_env.go` (neu): CEL-Env + `glob`-Funktion.
4. `internal/policy/sugar.go` (neu): Sugar-Validierung + -Kompilierung.
5. `internal/policy/policy.go`: Typen, `Load`, `Evaluate` neu schreiben; alte Baum-Typen löschen.
6. `internal/policy/policy_test.go`: komplett neu.
7. `internal/audit/audit.go`: `ToolName`-Feld ergänzen.
8. `cmd/hookguard/main.go`: `hookInput`-Dekodierung, `decide()`-Extraktion, PowerShell-Sonderfall, Segment-Loop über neues `Evaluate`.
9. `cmd/hookguard/main_test.go`: neu.
10. `config/gate.yaml` → `config/hookguard.yaml`: neu schreiben (umbenennen + neues Schema).
11. `README.md` und `CONTEXT.md`: neu schreiben bzw. Titel anpassen.
12. `go build ./... && go test ./...`, `make lint`.

## Kritische Dateien

- `go.mod` (Modul-Umbenennung + neue Dependencies)
- `Makefile` (Binary-/Install-Name)
- `internal/policy/policy.go`
- `internal/policy/cel_env.go` (neu)
- `internal/policy/sugar.go` (neu)
- `internal/policy/policy_test.go`
- `cmd/hookguard/main.go` (verschoben von `cmd/ctool-gate/main.go`)
- `cmd/hookguard/main_test.go` (neu)
- `internal/audit/audit.go`
- `config/hookguard.yaml` (verschoben von `config/gate.yaml`)
- `README.md`, `CONTEXT.md`
