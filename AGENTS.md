# AGENTS.md

Guidance for AI coding agents working in the minimega repository.

## Project Overview

minimega is a distributed virtual machine and container orchestration platform
written in Go. It launches and manages KVM VMs and Linux containers across a
single host or a cluster, coordinating them over a custom mesh network
(`meshage`). The Go module version and toolchain are declared in `go.mod` —
always check there rather than assuming a version.

## Repository Structure

- `cmd/` — entry points for each binary. Each subdirectory is a `package main`
  that builds to a standalone binary.
  - `miniccc/` — the in-VM/host agent ("command and control") client
  - `minidoc/` — documentation server/generator
  - `minimega/` — the core daemon/CLI; by far the largest and most active package
  - `minirouter/` — software router agent
  - `minitest/` — test harness for minimega scripts
  - `miniweb/` — web UI server
  - `nfcat/` — read minimega binary netflows. minimega's `capture` API can write netflow records in a binary format which can be read with nfcat. nfcat dumps the records to stdout in ASCII format.
  - `passwordify/` — modify credentials for ramdisk images, either root password or root SSSH keys.
  - `apigen/`  — generate CLI/API docs
  - `plumbing/` - [Plumbing](doc/content/articles/plumbing.article) is a facility in minimega to enable communication between VMs, processes on guests or hosts, and instances of minimega.
  - `powerbot/` — [powerbot](doc/content/articles/powerbot.article) is a tool in the vein of LLNL's "powerman" which can control outlets on networked Power Distribution Units (PDUs)
  - `protonuke/` — [protonuke](doc/content/articles/protonuke.article) is a simple, standalone, configuration-less traffic generator for IP networks
  - `pyapigen/` — generate Python bindings
  - `ranger/` - small utility that is old and unmaintained
  - `rfbplay/` — [rfbplay](doc/content/articles/vnc.article) plays vnc recordings created by minimega using `vnc fb record` in the browser or transcribes them using ffmpeg.
  - `rond/` - rond is a standalone command-and-control server with its own CLI to control physical machines running miniccc.
  - `vmbetter/` — vmbetter is a tool that takes a configuration file and outputs a minimega-bootable, Debian-based VM.
  - `vmconfiger` - vmconfiger generates the `vm config` APIs automatically for minimega. Only developers that are changing the VMConfig structs will need to use this. It runs automatically with `go generate`.
  - `vncdrone/` - vncdrone takes VNC kb/mouse recordings and replays them on compatible VMs. It looks at the recording filename, finds VMs using a disk with a matching filename (modulo the file extension), and start the vnc replay on all matching VMs.
- `internal/` — shared internal packages used by the `cmd/` binaries:
  `bridge` (OVS bridge mgmt), `qemu`/`qmp` (VM control), `meshage` (mesh
  networking), `miniplumber`, `iomeshage`, `nbd`, `ron` (cc protocol),
  `vlans`, `vnc`, `vmconfig`, `version`, `recovery`, `gonetflow`.
- `pkg/` — reusable public-ish packages: `minicli` (CLI framework used by all
  daemons), `miniclient`, `minilog`, `minipager`, `ranges`.
- `lib/` — Python bindings (`setup.py`, generated `minimega.py` by `pyapigen`).
- `doc/` — documentation site sources (`content/`, `content_templates/`,
  `template/`); built via `scripts/doc.bash` using `apigen`.
- `scripts/` — build/test/check/install entry points (bash). See
  "Build & Run" below.
- `tests/` — end-to-end `.mm`/script test cases, each with a matching
  `*.want` expected-output file, run against a live minimega instance.
- `misc/` — init scripts, daemon files, `vmbetter` configs, App Engine bits.
- `packages/`,  — vendored replacement Go modules.
- `packaging/` - Debian and RPM packaging files.
- `docker/` — Docker image and compose setup for running minimega in a container.
- `web/` — web UI static assets served by `miniweb`.

## Tech Stack

- **Language:** Go (see `go.mod` for the exact version — currently targets
  Go 1.24+). Vendored dependencies live in `vendor/` (`GOFLAGS=-mod=vendor`,
  set in `scripts/env.bash`).
- **Python bindings:** generated into `lib/` via `pyapigen`, packaged with
  `setup.py`/`build`.
- **Frontend:** minimal static JS/CSS under `web/` for `miniweb`.
- **Runtime dependencies (Linux only):** QEMU/KVM, Open vSwitch, dnsmasq,
  iproute2, ISC DHCP client, ntfs-3g, libpcap. See
  `.github/workflows/build.yml` for the exact `apt-get install` list.

## Build & Run

All build/test/check scripts live in `scripts/` and source
`scripts/env.bash` (sets `GOBIN` and `GOFLAGS=-mod=vendor`). They also
regenerate `internal/version/version.go` from `VERSION` + the current git
revision before building — don't hand-edit that generated file.

- `./scripts/all.bash` — runs check, build, test, and doc generation in order
  (mirrors CI in `.github/workflows/build.yml`).
- `./scripts/build.bash` — `go install`s every binary in `cmd/` (Linux), plus
  Windows cross-builds for `protonuke`/`miniccc`, then builds the Python
  bindings in `lib/`.
- `./scripts/check.bash` — runs `gofmt -d -l` and `go vet` across
  `cmd/`, `internal/`, `pkg/` (excluding `cmd/plumbing`).
- `./scripts/test.bash` — runs `go test` per-package across
  `cmd/`, `internal/`, `pkg/`.
- `./scripts/doc.bash` — regenerates `doc/content/articles/*.article` via
  `apigen`, reflecting on the built `minimega`/`minirouter` binaries.
- `./scripts/install.bash` — installs the systemd/init daemon files.
- `./scripts/clean.bash` — cleans build artifacts.

minimega itself requires Linux with QEMU/KVM and Open vSwitch to actually run
VMs; most development (build/vet/unit tests) works on any platform with Go,
but full behavioral testing needs a Linux host (see `tests/`).

## Testing

- **Unit tests:** standard `go test`, run via `./scripts/test.bash` or
  directly (e.g. `go test ./cmd/minimega/...`). Test files follow the
  standard `_test.go` convention (e.g. `cmd/minimega/vm_cli_test.go`... check
  package for `*_test.go` files before assuming coverage).
- **End-to-end tests:** `tests/<name>` are minimega script/`.mm` files with a
  matching `tests/<name>.want` file holding expected output — run against a
  live minimega instance (requires the Linux runtime dependencies above).
  When adding a new e2e scenario, add both the test script and its `.want`
  file.
- CI (`.github/workflows/build.yml`) runs `./scripts/all.bash` on Ubuntu with
  the full virtualization toolchain installed, on every push (see "CI/CD"
  below for a gap to be aware of).

## Key Patterns and Conventions

- **CLI handler pattern:** each `cmd/minimega/*_cli.go` file defines a
  `var xCLIHandlers = []minicli.Handler{...}` slice describing one command
  group (help text, patterns, and a handler function). All handler slices
  are wired up in one place: `registerHandlers("x", xCLIHandlers)` calls
  inside `cliSetup()` in `cmd/minimega/cli.go`. The CLI parsing/dispatch
  engine itself lives in `pkg/minicli/`.
- **Copyright headers:** most `.go` files start with a Sandia/NTESS copyright
  header comment. Preserve the existing header style when editing a file;
  use the header already present in the surrounding package for new files.
- **Formatting:** Go code is tab-indented (`gofmt` enforced by
  `check.bash`); `.editorconfig` governs other file types (4-space Python,
  2-space YAML). Run `gofmt` before committing.
- **Vendoring:** dependencies are vendored (`vendor/`) and `GOFLAGS=-mod=vendor`
  is set by `scripts/env.bash`. After changing `go.mod`/`go.sum`, run
  `go mod vendor` so `vendor/` stays in sync.
- **Generated files:** `internal/version/version.go` is regenerated by every
  build/test/check script from `VERSION` + `git rev-parse HEAD` — never edit
  it directly, and don't rely on its committed contents being current.
- **Local module replacements:** `go.mod` has several `replace` directives
  pointing at `packages/github.com/...` — these are internal forks of
  third-party libraries. Modify the vendored fork in place, not upstream.

## Adding a New CLI Command Group (cmd/minimega)

1. Create `cmd/minimega/<name>_cli.go` with a `var <name>CLIHandlers = []minicli.Handler{...}`.
2. Implement the handler function(s) referenced by the handlers (often in a
   sibling `<name>.go` file for the underlying logic).
3. Register the group in `cliSetup()` in `cmd/minimega/cli.go`:
   `registerHandlers("<name>", <name>CLIHandlers)`.
4. If the command should appear in generated docs, ensure it's covered by
   one of the `-sections` passed to `apigen` in `scripts/doc.bash`.
5. Add unit tests (`<name>_cli_test.go` / `<name>_test.go`) and, if the
   command needs behavioral coverage, an end-to-end case under `tests/`
   with a matching `.want` file.
6. Update CODEOWNERS if the new file lives outside the directories already
   listed there (it usually won't, since `/cmd/` is already covered).

## CI/CD

- `.github/workflows/build.yml` — builds all binaries + Python dist via
  `scripts/all.bash` on Ubuntu with virtualization packages installed. Runs
  on `push` (and `release`), but **has no `pull_request` trigger**, so it
  only runs on pushes to branches in this repo, not automatically on PRs
  from forks — keep this in mind when validating changes before merge.
- `.github/workflows/deb.yml` / `rpm.yml` — build Debian/RPM packages.
- `.github/workflows/docker.yml` — builds/pushes the Docker image on push.
- `.github/workflows/python-publish.yml` — publishes the Python bindings on
  release.
- `.github/workflows/release.yml` — manual (`workflow_dispatch`) release flow.

## Documentation

- API/CLI reference docs are generated, not hand-written: `scripts/doc.bash`
  runs `apigen` against the built `minimega`/`minirouter` binaries and the
  templates in `doc/content_templates/`, emitting `.article` files into
  `doc/content/articles/`. If you add or change CLI handlers' help text
  (`HelpShort`/`HelpLong` in a `*_cli.go` file), the docs pick it up
  automatically the next time `doc.bash` runs — don't hand-edit the
  generated articles.
- Published docs live at [sandia.gov/minimega](https://www.sandia.gov/minimega/).
- `doc/template/` holds the site's HTML templates (article/layout/slides).

## Common Pitfalls

- Don't hand-edit `internal/version/version.go` — it's regenerated on every
  build/test/check run.
- Don't forget `GOFLAGS=-mod=vendor` (set via `scripts/env.bash`) — running
  bare `go build`/`go test` without sourcing it, or after adding a
  dependency without `go mod vendor`, can fail or silently use the wrong
  module version.
- Full VM/container behavior (KVM, OVS, dnsmasq) only works on Linux with
  root/appropriate privileges; don't expect `tests/` e2e cases to pass in a
  plain sandboxed container without those dependencies.
- When adding a CLI command, forgetting the `registerHandlers(...)` call in
  `cmd/minimega/cli.go` means the handler slice is defined but never wired
  up — it will compile but the command won't exist at runtime.

## Branches and commits

Branch names should follow conventional commit style and use kebab-case, with no slash characters, e.g. `fix-bug-1234`, `feat-new-feature`, `chore-update-deps`. Commit messages should also follow conventional commit style, with a clear and concise description of the change. Each commit should be atomic and focused on a single change or fix.

## Pull Request standards

Pull Requests should follow the template in [PULL_REQUEST_TEMPLATE.md](PULL_REQUEST_TEMPLATE.md). They should be concise and to the point. PR titles must follow Conventional Commit style (`fix:`, `feat:`, `chore:`) and should be descriptive of the change. The PR description should include a summary of the change, any relevant context, and any additional information that may be helpful for reviewers, while staying concise. If the PR is a work in progress, mark it as a draft.
