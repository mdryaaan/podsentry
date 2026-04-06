# 🛡️ podsentry

**Static security auditing for Kubernetes Pod specs — no cluster required.**
Point it at a YAML file or a whole manifest repo and get a Pod Security Standards, user namespace, and SecurityContext report back in seconds.

[![CI](https://github.com/mdryaan/podsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/mdryaan/podsentry/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mdryaan/podsentry?color=00ADD8&logo=github)](https://github.com/mdryaan/podsentry/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Pod%20Security%20Standards-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
[![cobra](https://img.shields.io/badge/CLI-cobra-00ADD8?logo=go&logoColor=white)](https://github.com/spf13/cobra)

![podsentry --help](public/screenshots/home.png)

<table>
  <tr>
    <td><img src="public/screenshots/inspect.png" alt="podsentry inspect" width="420"></td>
    <td><img src="public/screenshots/pss.png" alt="podsentry pss --recursive" width="420"></td>
  </tr>
  <tr>
    <td align="center"><code>podsentry inspect</code></td>
    <td align="center"><code>podsentry pss ./examples --recursive</code></td>
  </tr>
  <tr>
    <td><img src="public/screenshots/userns.png" alt="podsentry userns" width="420"></td>
    <td align="center" valign="middle">Works entirely offline against files on disk.<br>No cluster, no admission webhook, no live API server.</td>
  </tr>
  <tr>
    <td align="center"><code>podsentry userns</code></td>
    <td></td>
  </tr>
</table>

## Features

- 🛡️ **All three Pod Security Standard levels** — Privileged, Baseline, and Restricted, with rule logic matching the upstream Kubernetes definitions
- 🔐 **User namespace inspection** — reads `hostUsers` and explains the resulting UID/GID mapping and container-escape blast radius
- 🧬 **Linux capability auditing** — checks added and dropped capabilities against the safe baseline set
- ⬆️ **Privilege escalation checks** — `allowPrivilegeEscalation`, `runAsNonRoot`, `runAsUser`, `runAsGroup`
- 🧱 **Seccomp profile checks** — at both the pod and container level
- 🌐 **Host namespace checks** — `hostNetwork`, `hostPID`, `hostIPC`, and host ports
- 🔎 **Combined `inspect` report** — merges PSS, user namespace, and SecurityContext findings into one view
- 📄 **JSON output** for pipelines, 🎨 **colored tables** for humans
- 📂 **Recursive directory scanning** — audit an entire manifest repository in one pass
- 🚦 **`--exit-code` CI gating** — non-zero exit on any violation, so it fails a build like a test would
- ⚙️ **GitHub Action included** — drop it into any workflow, no Go toolchain needed
- 🔌 **100% offline** — no cluster, no admission webhook, no external services

## Commands

| Command | Description |
|---|---|
| `podsentry pss pod.yaml` | Check a Pod against the Pod Security Standards (defaults to `restricted`) |
| `podsentry pss pod.yaml --level restricted` | Check against a specific level: `privileged`, `baseline`, or `restricted` |
| `podsentry pss ./manifests/ --recursive --exit-code` | CI-friendly recursive directory scan with a non-zero exit on failure |
| `podsentry userns pod.yaml` | Inspect `hostUsers` configuration and UID mapping implications |
| `podsentry securitycontext pod.yaml` | Audit capabilities, privilege escalation, seccomp, and host namespaces |
| `podsentry inspect pod.yaml` | Full combined PSS + userns + SecurityContext report |
| `podsentry version` | Show version info |
| `podsentry completion [shell]` | Generate shell completion scripts |

Every command accepts `--json` for machine-readable output instead of a table.

## What are Pod Security Standards?

The [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) are Kubernetes' own definition of three security profiles a Pod can be checked against:

- **Privileged** — unrestricted, for trusted system/infra workloads.
- **Baseline** — blocks known privilege escalations (privileged containers, host namespaces, hostPath volumes, disallowed capabilities) while staying broadly compatible with common workloads.
- **Restricted** — the hardened profile: on top of Baseline, it requires running as a non-root user, dropping all capabilities, disallowing privilege escalation, and enforcing a seccomp profile.

Clusters normally enforce these at admission time via the built-in Pod Security Admission controller. podsentry lets you check the same rules **before** a manifest ever reaches a cluster — in a pre-commit hook, in CI, or just on your laptop.

## What are User Namespaces?

Kubernetes can run a Pod in its own **user namespace** (`hostUsers: false`), remapping container UIDs/GIDs to an unprivileged, pod-specific range on the host. A process that looks like root (UID 0) *inside* the container is an ordinary unprivileged user *outside* of it, which significantly limits the blast radius of a container-to-host escape.

`podsentry userns` reads the `hostUsers` field, tells you which mode a Pod is running in, explains the mapping implications in plain language, and flags configurations that conflict with an isolated user namespace — privileged containers, host namespace sharing, and hostPath volumes are all incompatible with `hostUsers: false`.

## Tech stack

| Component | Purpose |
|---|---|
| [Go 1.22+](https://go.dev) | Language / runtime |
| [cobra](https://github.com/spf13/cobra) | CLI command framework |
| [k8s.io/api](https://pkg.go.dev/k8s.io/api) | Core Kubernetes types (Pod, PodSpec, SecurityContext) |
| [k8s.io/apimachinery](https://pkg.go.dev/k8s.io/apimachinery) | Object handling shared by the Kubernetes API types |
| [gopkg.in/yaml.v3](https://pkg.go.dev/gopkg.in/yaml.v3) | YAML parsing |
| [tablewriter](https://github.com/olekukonko/tablewriter) | Table rendering for human output |
| [fatih/color](https://github.com/fatih/color) | Colored terminal output |

No database. No external services. No cluster dependency.

## Architecture

![podsentry architecture](public/screenshots/arch.png)

`internal/loader` is the only package that touches the filesystem. Every check package (`pss`, `userns`, `securitycontext`) operates purely on an in-memory `corev1.PodSpec` and has no I/O of its own, which is what makes them straightforward to unit test.

## Use it in CI

The repository ships a GitHub Action, so no Go toolchain or manual install is needed:

```yaml
# .github/workflows/podsentry.yml
name: podsentry
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mdryaan/podsentry@v0
        with:
          path: ./manifests
          level: restricted
          recursive: true
```

The action writes the full report to the job summary and fails the build on any violation.

`@v0` is a floating tag that tracks the latest `v0.x` release, so bug fixes arrive automatically.
Pin an exact version (`@v0.1.1`) instead if you would rather upgrade deliberately.

### Action inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | File or directory of Pod manifests to audit |
| `command` | `pss` | `pss`, `inspect`, `userns`, or `securitycontext` |
| `level` | `restricted` | `privileged`, `baseline`, or `restricted` (used by `pss`) |
| `recursive` | `true` | Recursively scan directories |
| `fail-on-findings` | `true` | Fail the job when any Pod is non-compliant |
| `json` | `false` | Emit JSON instead of a table |
| `version` | `latest` | Pin a specific podsentry release |

### Action outputs

| Output | Description |
|---|---|
| `report` | Path to the report file |
| `compliant` | `true` when every scanned Pod passed |

Report findings without failing the build — useful when adopting it on an existing repo:

```yaml
      - uses: mdryaan/podsentry@v0
        id: audit
        with:
          path: ./manifests
          fail-on-findings: false
      - run: echo "compliant=${{ steps.audit.outputs.compliant }}"
```

### Without the action

`--exit-code` makes any command exit non-zero on a violation, so it gates a job the same way a test failure would:

```bash
podsentry pss ./manifests --recursive --level restricted --exit-code
```

## Install

**Download a release binary** (no Go toolchain required) — see [Releases](https://github.com/mdryaan/podsentry/releases):

```bash
VERSION=0.1.1
curl -sSfL "https://github.com/mdryaan/podsentry/releases/download/v${VERSION}/podsentry_${VERSION}_linux_amd64.tar.gz" \
  | tar -xz podsentry
sudo mv podsentry /usr/local/bin/
podsentry version
```

Binaries are published for Linux, macOS, and Windows on both amd64 and arm64, with SHA256 checksums and an SBOM attached to every release.

**With Go:**

```bash
go install github.com/mdryaan/podsentry@latest
```

**From source:**

```bash
git clone https://github.com/mdryaan/podsentry.git
cd podsentry
make build
./podsentry --help
```

## Example usage

```bash
# Check a single pod against the restricted level (the default)
./podsentry pss examples/restricted-pod.yaml

# Check against a specific level
./podsentry pss examples/baseline-pod.yaml --level baseline

# Recursively scan a manifest repository and fail CI on any violation
./podsentry pss ./examples --recursive --exit-code

# Inspect user namespace configuration
./podsentry userns examples/userns-enabled-pod.yaml

# Audit SecurityContext settings
./podsentry securitycontext examples/noncompliant-pod.yaml

# Full combined report
./podsentry inspect examples/restricted-pod.yaml

# JSON output for scripting
./podsentry inspect examples/restricted-pod.yaml --json
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for dev environment setup, how to add a new PSS rule or report formatter, and PR guidelines.

## Roadmap

- [ ] Kustomize and Helm chart rendering support (audit templates, not just static Pods)
- [ ] Namespace-scoped PodSecurity label validation (compare a namespace's enforce/warn/audit labels against actual Pods)
- [ ] SARIF output for GitHub code scanning integration
- [ ] Config file support for custom capability allowlists and rule suppression
- [ ] `--diff` mode to show only what changed between two scans

## License

MIT — see [LICENSE](LICENSE).
