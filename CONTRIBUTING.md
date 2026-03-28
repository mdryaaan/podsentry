# Contributing to podsentry

Thanks for taking a look at podsentry. This document covers everything you
need to get a dev environment running and to send a useful pull request.

## Prerequisites

- Go 1.22+
- `make` (optional, but the Makefile targets are the easiest way to run things)

## Dev environment setup

```bash
git clone https://github.com/mdryaan/podsentry.git
cd podsentry
go mod download
go build -o podsentry ./main.go
./podsentry --help
```

Run the test suite before you start, so you know your baseline is green:

```bash
go test ./... -cover
```

## Project layout

```
cmd/                  cobra command definitions, one file per subcommand
internal/loader/      reads and parses Pod YAML from disk
internal/pss/         Pod Security Standards rule definitions and evaluator
internal/userns/      hostUsers inspection and UID mapping explanations
internal/securitycontext/  capabilities/privilege/seccomp/host-namespace analysis
internal/report/      table and JSON rendering shared by all commands
internal/utils/       small PodSpec/container helpers shared across packages
pkg/version/          build-time version metadata
examples/             sample Pod manifests used in the README and by hand-testing
```

## Adding a new PSS rule

Rules live in `internal/pss/baseline.go` and `internal/pss/restricted.go` as
`Rule` values returned from `BaselineRules()` / `RestrictedRules()`. To add
one:

1. Pick a unique, kebab-case `ID` prefixed with the level it belongs to
   (e.g. `restricted-my-new-rule`).
2. Write the `Check` function. It receives a `corev1.PodSpec` and returns
   `[]Finding`, one per offending container (or a single pod-level finding
   with an empty `Container` when the issue isn't container-specific).
3. Add the rule to the slice returned by `BaselineRules()` or
   `RestrictedRules()`.
4. Add a test in the matching `_test.go` file. Follow the existing pattern:
   build a compliant spec, mutate one field to violate the rule, assert the
   rule fires with `assertHasRule`.

Keep rule logic matching the upstream Kubernetes Pod Security Standards
definitions — link the relevant upstream doc section in the PR description
if the rule isn't obvious from its name.

## Adding a new report formatter

Report rendering lives in `internal/report/`. `PodReport` (in `report.go`)
is the shared shape every formatter consumes; it's built once per pod in
each `cmd/*.go` command and handed to whichever formatter the `--json` flag
selects.

To add a new formatter:

1. Add a `Render*` (table-like) or `Write*` (stream-like) function in
   `internal/report/`, taking `io.Writer` and `[]PodReport` and following
   the signature style of `RenderPSSTable` / `WriteJSON`.
2. Wire it into the relevant command in `cmd/` behind whatever flag selects
   it.
3. Add a test in `report_test.go` if the formatter has non-trivial logic
   (JSON encoding, summary math). Purely visual table output doesn't need a
   test beyond compiling.

## Branch naming and commit messages

- Branches: `feat/<short-description>`, `fix/<short-description>`,
  `docs/<short-description>`, `chore/<short-description>`.
- Commits: `type(scope): summary`, e.g. `feat(pss): add restricted seccomp checks`.
  Scope is usually the package name (`pss`, `userns`, `securitycontext`,
  `report`, `cmd`, `loader`).

## PR guidelines

- Keep PRs focused on one rule, one command, or one bug fix. Large sweeping
  PRs are harder to review and harder to bisect later.
- Include a test for any new rule or bug fix.
- Run `go vet ./...` and `gofmt -l .` before opening the PR — both should be
  clean.
- Describe *why* the change is needed, not just what changed; link the
  upstream Kubernetes doc section for any new PSS rule.

## Code style

- No comments in implementation files except godoc comments on exported
  identifiers.
- No `TODO` comments — open an issue instead.
- Wrap errors with context: `fmt.Errorf("doing X: %w", err)`.
- No `panic` in library code (anything under `internal/` or `pkg/`); it's
  fine to `os.Exit` from `cmd/` for CI exit-code gating.
- Prefer small, composable functions over large ones with branching state.
