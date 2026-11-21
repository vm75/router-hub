# Modular platform and UI migration: Router Hub to Maestro

**Status:** Phase 1 merged to `main` as v0.10.5; Phase 1.5 Maestro rebrand implemented on its own branch, M1.5 validation pending  
**Phase 1.5 branch:** `refactor/rebrand-maestro`  
**Baseline:** `vm75/router-hub` `main` at `5e2013f031c965cf0381f868c541d60bb5eac602` (v0.10.4)  
**Source projects:** [router-hub](https://github.com/vm75/router-hub), [server-man](https://github.com/vm75/server-man)  
**Selected product name:** **Maestro** (`maestro`). The existing Go/Svelte **Server Man** remains a separate Phase 2 reference, not the chosen Rust project name.

## Executive decision and stopping points

Create one modular Rust management application with common modules, platform-specific implementations, and two lightweight-at-deployment UI shells. The ASUS router must retain all existing functionality. Linux gains Server Man's Svelte UI and Linux management capabilities **only in Phase 2**.

**Implement in this order:**

0. Baseline and test inventory (before structural edits).
1. **Phase 1, step 1:** backend capability/module contracts and logical UI contribution contracts.
2. **Phase 1, step 2:** reorganize Router Hub's Rust features and platform adapters without changing behavior.
3. **Phase 1, step 3:** modularize the existing ASUS UI into a common shell, one dashboard, and composable feature tabs/sections.
4. **STOP M1:** complete automated, package, and real ASUS-router feature-parity acceptance. Do not begin the next workstream or merge an incomplete Phase 1.
5. **Phase 1.5:** rebrand the validated project, including packaging/upgrade compatibility and GitHub repository collision resolution. Do not port Server Man features during the rebrand.
6. **STOP M1.5:** verify rebranded releases and existing-install migration. Only then begin Phase 2.
7. **Phase 2:** integrate the Svelte Linux shell and operation infrastructure, Linux services/monitoring/updates, Server Man's declarative Applications engine and native providers, then storage/shares and optional MCP/backup follow-ups.

**CI hold:** No automatic GitHub Actions CI on the planning/implementation branch before all three Phase 1 steps are implemented. The existing `ci.yml` triggers are already limited to pushes on `main` and `ci/**`, plus explicit `workflow_dispatch`; there is no ordinary PR trigger. Keep this branch named `refactor/modular-architecture`, **do not push it to `ci/**`, do not merge it into `main`, do not push `v*` tags, and do not manually dispatch CI until Phase 1 implementation is complete and ready for validation. No workflow edits are needed merely to achieve this hold. Keep existing `main` CI and separate manually triggered NGINX/toolchain workflows intact.

## Scope, boundaries, and non-goals

- **One backend:** Rust modular monolith, one service process per host. No dynamic Rust/JS plugins, microservices, or permanent Go sidecar.
- **Platforms:** `asuswrt` and `linux` initially; model future routers as adapters rather than branching feature logic throughout the code.
- **Core vs platform:** feature behavior and API contracts are shared where possible; platform operations depend on explicit adapters.
- **UI:** one persistent Dashboard; navigation tabs are logical groups that contain one or more feature sections. Each feature may contribute zero or more dashboard widgets. UI availability is driven by backend capabilities and permissions, never trusted as backend authorization.
- **ASUS:** preserve current build-free, offline-capable, embedded HTML/JS + ASP integration; do not require npm/Svelte, an external CDN, or runtime asset downloads on a router.
- **Linux:** keep current Router Hub real-Linux integration operational during Phase 1. Svelte 5/Vite is introduced in Phase 2 and compiled to static assets at build/release time.
- **Configuration:** preserve current Router Hub TOML and JSON, NGINX sites, state paths and migrations in Phase 1. Preserve Server Man's workload YAML semantics during the subsequent Rust port; avoid two authoritative server-settings documents.
- **Name:** do not rename packages, executables, API paths, menu labels, or config directories until after the M1 parity gate.
- **No functionality ported from Go during Phase 1:** no Docker/Podman/Incus/libvirt, Samba/NFS, Linux package-management features, new browser-session auth, or MCP.
- **No unplanned backend changes:** no new firewall implementation, NGINX renderer replacement, authentication redesign, storage-format conversion, or upgrade-flow redesign during structural work.

## Target module model

Three independent concerns must not be conflated:

| Concern | Responsibility | Example |
| --- | --- | --- |
| Feature/backend module | Domain logic, operations, data, requirements and health | NGINX, certificates, services, applications, Ban Shield |
| Platform/provider adapter | Executes operations for a target environment | Entware init vs systemd; ASUS DNSmasq vs Linux; Podman vs Docker vs libvirt vs Incus |
| UI contribution | Tab section, action, notification and optionally dashboard widget | Certificates section in Web tab; failed-services dashboard summary |

A **tab is not a backend module**. An Applications tab will aggregate all supported workloads; NGINX and certificates can share a Web tab. A feature need not register a tab of its own. A feature need not contribute any dashboard widget.

### Initial module ownership / target availability

| Module | Phase 1 origin | ASUS target | Linux target | Phase 2 origin |
| --- | --- | --- | --- | --- |
| NGINX sites, ingress, rendering, rollback | Router Hub | Existing behavior | Existing behavior / adapted runtime | Shared, unchanged domain |
| Certificates / ACME | Router Hub | Existing behavior | Existing compatible paths | Shared |
| Services | Router Hub | Entware `S*` init scripts | Existing Linux compatibility wrapper | Server Man systemd adapter |
| Monitoring and dashboard | Router Hub | Existing metrics | Existing metrics | Server Man richer sampler/processes |
| Ban Shield / firewall | Router Hub | Current ipset/iptables | Existing behavior, cautious support | Future Linux adapter only if justified |
| AdGuard Home / DNS | Router Hub | AdGuard + ASUS DNSmasq integration | Supported client; no ASUS NVRAM side effects | Optional Linux DNS adapter |
| WireGuard, Wake-on-LAN | Router Hub | Current behavior | As available | Shared |
| ASUS menu, Entware router/NGINX upgrades | Router Hub | Router-only | Never exposed | No port |
| Applications: containers and VMs | None | Unsupported | Not in Phase 1 | Server Man declarative coordinator/providers |
| Storage, Samba/NFS shares | None | Unsupported | Not in Phase 1 | Server Man |
| Linux OS package updates | None | Unsupported | Not in Phase 1 | Server Man |
| MCP / agent access | None | Unsupported | Not in Phase 1 | Optional Server Man port |

Every module should distinguish **unsupported** (not a target), **disabled** (configured off), **unavailable/degraded** (supported but dependency or permission missing), and **ready**. Do not hide missing dependencies inside generic disabled status. The backend rejects operations for unsupported/disabled modules even if a caller bypasses the UI.

### Backend contracts (illustrative, not prescribed public API)

- Static registry with immutable IDs, supported targets, required capabilities, enabled state, availability/health and dependencies.
- Adapter contracts for `ServiceManager` and other truly platform-specific operations; preserve existing semantics rather than forcing a misleading lowest-common-denominator abstraction.
- Services: inventory/details/status/logs, start/stop/restart, enable/disable, optional reload. Keep runtime state and boot enablement distinct.
- Optional additive `GET /api/modules` (or equivalent discovery endpoint) exposing non-secret capabilities/health and feature groups. Keep **all existing** `/api/*` endpoints and response contracts stable.
- Domain functions should not import HTTP handlers, browser components, or ASUS menu code. API handlers are adapters; command execution remains bounded and argument-based.
- Module assembly must preserve dependency ordering, background tasks, error behavior and shutdown.
- For future Linux app-owned systemd units, route actions through the Applications coordinator, not direct generic systemctl operations.

### UI contribution contract

A module declares stable identifiers, applicable backend capability IDs, optional tab sections and optional dashboard widgets. Composition is deterministic; no runtime code loading or plugin marketplace.

**Initial logical tabs on the ASUS UI (proposed grouping, subject to parity tests):**

| Tab | Sections | Dashboard |
| --- | --- | --- |
| Dashboard | Core system overview + contributed widgets | Always present |
| Services | Entware services | Optional service summary |
| Web | NGINX sites/settings/logs; certificates | Optional NGINX/certificate summaries |
| Security | Ban Shield, firewall policy/rules | Optional active-ban summary |
| Network | AdGuard, WireGuard, Wake-on-LAN | Optional integration/status summaries |

All currently accessible independent views (Dashboard, Services, NGINX, Certificates, Wake-on-LAN, Ban Shield, AdGuard, WireGuard) must remain accessible after grouping. If preserving existing view/tab IDs as aliases is simpler or safer than immediate grouping, implement aliases and migrate navigation gradually. Preserve all forms, actions, modals, error/success feedback, accessibility, refresh behavior, deep links, IDs used by scripts, and ASUS ASP rendering. The visual layout may be reorganized; **functional parity is mandatory**.

For Linux in Phase 2, the same logical contract can add Applications (Podman Quadlet, Podman Compose, Docker Compose, libvirt, Incus), File Sharing, Updates, expanded Monitoring, Configuration and Agent Access without creating one top-level tab per provider.

**Dashboard rules:**

1. Dashboard is always available even if all optional contributors are unavailable.
2. A module may contribute zero, one or multiple compact summaries; no contribution is mandatory.
3. Each widget has its own loading/error/refresh lifecycle and cannot block other widgets.
4. Failed reads are surfaced as unavailable/stale, not silently treated as zero or healthy.
5. Summaries link to their owning tab/section where applicable. Avoid a global dashboard that duplicates all module pages.
6. Widget placement/order is deterministic in Phase 1; user customization is deferred.

## Phase 1 implementation record (M1 not signed off)

The implementation branch now contains static module discovery and UI
contributions, a protected additive `/api/modules` endpoint, legacy-compatible
domain and platform adapters, and a build-free split ASUS UI source composed
into the same self-contained `web/index.html`. Existing API routes, CLI
commands, package name, version and persistent configuration are unchanged.

The compatibility inventory and remaining manual/automated acceptance work are
tracked in [Phase 1 compatibility and validation](../../phase1-compatibility.md).
A JavaScript syntax check has been performed; the full Rust test suite, ARM IPK,
native-Linux smoke, browser workflows, GitHub CI and physical ASUS validation
**must still be run**. No Phase 1.5 rebrand or Phase 2 port is included.

## Baseline / pre-work (gate B0)

Before changing architecture, capture comparisons against an unchanged `main` checkout:

- Record current Rust version (`1.85+`), package version, CLI help/options, exact startup/shutdown/upgrade command restrictions, normal and test-mode configuration behavior.
- Record existing API routes and representative success/error JSON, auth/origin enforcement, configuration defaults and validation errors.
- Record current UI navigation and browser workflows; capture standalone rendered HTML and injected ASP (including the current `<style>` / `<body class="rh-page">` extraction expectations); identify inline handlers and DOM selectors used in tests.
- Inventory persistent state files and update/migration paths; include rollback behavior and crash/restart recovery where existing.
- Run available local fixtures and tests: `cargo fmt --all -- --check`, `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo build --release --locked`, `scripts/test-nginx-ui.mjs`, NGINX template tests when local dependencies are present, `scripts/test-package-ipk.sh`, `make test-linux` where host dependencies permit.
- Capture a representative ASUS hardware baseline **on the matching router**, if available: Entware service actions, menu injection, NGINX lifecycle, HTTPS/certificate flows, Ban Shield, DNSmasq and AdGuard, WireGuard, WOL, idle RSS/CPU, cold start and package contents. Avoid writing production firewall rules solely for a baseline; use safe/observational checks and a disposable test scope where applicable.
- Keep baseline artifacts and review notes in safe test fixtures or private test records; **do not commit tokens, private keys, real router logs, `data/`, or live configuration secrets**.

Acceptance: a reproducible inventory and test plan exists before a file move. Existing failing tests or unavailable dependencies are recorded, not silently reclassified as passing.

## Phase 1 — behavior-preserving Router Hub modularization

### Step 1 — Declare module/capability and UI composition contracts

**Deliverables**

- Define stable backend module IDs, platform targets, capability/availability states, and module dependency validation.
- Introduce a minimal static registry and additive discovery representation, avoiding speculative plugin loading.
- Define framework-independent UI contribution manifest: tab IDs, section IDs, widget IDs, ordering, prerequisites and lightweight read-only status.
- Establish a compatibility map of current URL paths, API routes, menu names, command names and persistent paths.
- Add tests for module assembly on `asuswrt` and `linux`, unsupported/disabled checks, duplicate IDs, dependency resolution and serialization.
- Document upgrade/rollback strategy and baseline measurements.

**Acceptance:** existing configs and route behavior remain unchanged. Router build has no new runtime/frontend dependencies; the registry can describe current features without changing their execution.

### Step 2 — Restructure Rust backend and platform adapters

**Deliverables**

- Move code in small, reviewable units to `core/`, `modules/` and `platforms/` as justified. Begin with simpler boundaries (system usage, WOL, Services), then larger domains.
- Centralize module initialization and route assembly; keep current API endpoints as compatibility routes.
- Extract platform-specific services (Entware init) and ASUS integration (menu/ASP, DNSmasq/NVRAM, Entware-only upgrades) without changing the underlying operations.
- Introduce `ServiceManager` for Entware first; **do not implement the Server Man systemd service manager in Phase 1**. Keep existing real-Linux behavior working with its existing compatible scripts.
- Preserve NGINX render/rollback, certificate/HTTP-01 sessions, Ban Shield enforcement/ownership, DNS settings, WireGuard and WOL behavior and error surfaces.
- Preserve command runner safety, locks, atomic stores, filesystem symlink protections and startup/reconcile ordering.
- Keep the default platform/`platform = "asuswrt"` serialization and current `--linux-mode` / `--test-mode` compatibility rules.
- Keep version, binary name, init scripts, IPK metadata, updater/release lookup and packaging unchanged.

**Acceptance:** source reorganized without functionality changes; existing tests pass locally, API contract fixtures match, Linux integration smoke works, and the ASUS package remains self-contained. Do not claim hardware equivalence yet.

### Step 3 — Modularize existing ASUS UI

**Deliverables**

- Extract shell/navigation/dashboard and feature-specific view/render/event logic from `web/index.html` into maintainable source pieces with a deterministic **build-free** embedding/composition path.
- Retain a **single self-contained offline UI payload** at runtime, compatible with `src/asus_ui.rs` and `config/asus-wrt.asp.template`. Do not require npm, a CDN or runtime file fetching.
- Implement tab/section composition and optional dashboard contributors using the same backend capability identifiers.
- Consolidate logical tabs as appropriate (e.g. Web includes NGINX and certificates; Network includes AdGuard, WireGuard and WOL). Preserve previously reachable features and any required existing selectors/deep-link behavior via mapping/aliases.
- Keep existing token handling, login/auth errors, visual status, user feedback, NGINX editors, modal flows, and browser/Axum API behavior. Avoid introducing a new browser authentication mechanism on ASUS.
- Add UI-level tests covering tab registration/ordering, all enabled feature sections, empty dashboard contributors, partial failures, unsupported modules, standalone and ASP rendering.
- Add test coverage for composed HTML/JS correctness; verify inline functions and browser global scope still work when mounted into ASUS firmware.

**Acceptance:** no missing, broken or inaccessible router workflows; offline standalone/ASP pages work; no extra runtime asset requests; UI still packages in the Entware IPK. This completes implementation of Phase 1 **but not yet hardware sign-off**.

### M1 — hard feature-parity gate (PAUSE HERE)

Run validation only after Steps 1–3 are implemented. The first GitHub CI run is an **explicit manual `workflow_dispatch`** on the branch or its PR number; do not create `ci/**` branches merely to make CI run automatically. Fix all failures on the feature branch. A passing CI run is necessary but not sufficient.

| Functional area | Required parity evidence |
| --- | --- |
| Router startup / ASUS menu | Boot/init script, ASP rendering, menu integration, restart/shutdown unaffected |
| Dashboard / UI | Every original feature, form and action reachable; all widgets optional and independent |
| Auth / API | Bearer token and origin protections; unchanged existing routes, JSON and errors |
| NGINX | Test, start/reload/stop, site CRUD, inherited settings, ingress/access previews, logs, render validation and rollback |
| Certificates | Issue/renew, DNS-01/HTTP-01, dehydrated locking, scoped firewall challenge window and failure recovery |
| Ban Shield / firewall | Observe-only, policy CRUD, allowlists, bans/unbans, reconciliation and bounded log processing |
| AdGuard / DNSmasq | Config, filtering/protection timers, rewrites, router-specific hosts and DNS restart behavior |
| WireGuard / WOL | Interface/peer controls, status, device CRUD/reachability/wake |
| Services | Entware listing, lifecycle, enable/disable, logs, protected Router Hub init entry |
| CLI / storage | backup/restore, schema compatibility, state persistence, router-only upgrade and upgrade-nginx guards |
| Linux compatibility | Existing native-linux smoke, no unexpected ASUS NVRAM/menu/firewall effects |
| Packaging | IPK layout, postinst ordering/migrations, clean install and in-place upgrade |
| Footprint | Measure ARM router binary size, startup time, idle CPU and RSS; explain/reject material regressions |

**Exit requirements:** local checks + manually invoked GitHub CI pass, regression fixtures pass, matching ASUS router hardware is tested, operator signs off behavior and footprint, rollback/recovery instructions are verified, and Phase 1 commits are reviewed. **No Phase 2 code or rebrand is mixed into M1.** Once validated, Phase 1 can merge to `main` (which intentionally invokes the normal main CI/release policy) and receive its own stable tag/release before rebranding.

## Phase 1.5 — Maestro rebrand (implementation completed; validation pending)

Phase 1 is merged on `main` as v0.10.5. This rebrand is implemented on
`refactor/rebrand-maestro` and must not be mistaken for a released, hardware-validated package.
The new Rust project identity is **Maestro**, including the `maestro` crate, binary,
Entware IPK, `S99maestro` init script, new-install config path and UI. The
existing artwork is merely renamed and can be replaced by the maintainer.

The GitHub repository is **still** `vm75/router-hub`. Renaming a repository is a
separate GitHub administrative action after merge and release readiness; source
code branches cannot perform that rename. Both the Rust self-updater and the
custom NGINX updater retain the currently reachable release endpoint until
the repository is actually renamed. The unrelated Go project at
`vm75/server-man` remains untouched and may be used as a Phase 2 port reference.
The earlier Server Man repository-name collision is no longer relevant.

**Migration strategy:** ship the new `maestro` package with an explicit
`Conflicts: router-hub` constraint, and a CLI-only `router-hub` symlink.
Operators first back up then remove the old Entware package, then install a
verified published Maestro IPK. On first install only, the setup helper
adopts the legacy TOML into the new configuration file, preserving tokens,
NGINX inputs, policy/state paths and legacy firewall ownership identifiers;
it copies legacy dehydrated binary data when available, and rewrites
packaged dehydrated hook references in the *new* configuration only.
Original user data and config remain untouched for rollback. Old JFFS
reconciliation hooks are updated to call `S99maestro` without duplication.
No automatic legacy package uninstall, force-overwrite, state relocation,
or change to the exposed API endpoints is permitted.

Full instructions and rollback procedures:
[Maestro migration guide](../../maestro-migration.md).

**M1.5 exit gate:** Verify fresh install, Router Hub v0.10.5 upgrade,
restart/boot, API/auth/UI/ASP and router feature parity, existing NGINX
configuration and certificates, firewall state continuity, native Linux smoke,
Entware metadata and safe rollback. Run local CI/tests and release packaging.
Do not start porting the Go Server Man capabilities until acceptance.

## Phase 2 — port Server Man features into Maestro

Keep the Go implementation available as the behavior/specification reference. Implement vertical slices, each with Rust domain tests, API contract tests, frontend integration and native Linux acceptance. Do not translate Go line by line or erase its native recovery guarantees.

### Step 4 — Linux UI shell, operations bridge and authentication

- Reuse Server Man's Svelte 5/Vite shell and responsive styles; compile to static assets only in the Linux release. Keep ASUS build and IPK free of the Svelte build toolchain/assets.
- Adapt the existing Svelte `invokeTool`/`startJob` client: preserve or provide a compatible `POST /api/tools/{name}` transport, tool/module discovery, tracked jobs and predictable JSON error codes. Keep Router Hub's existing REST endpoints working.
- Port the core registry concepts (schema validation, read/write policy, bounded output, management-job locking, audit, cancellation) into Rust incrementally.
- Port Linux browser session flow and Host/Origin protection; do not change ASUS bearer-token behavior. Require explicit permission boundaries for privileged Linux actions.
- Establish a shared navigation/dashboard contribution contract; Linux tab assembly uses Svelte components and lazy loading, while ASUS keeps its embedded renderer.
- Gate with Linux UI login/auth, discovery, job lifecycle, responsive routing and no regression to ASUS paths.

### Step 5 — Linux systemd Services adapter and shared Services UI

- Port Server Man's system/user `systemctl` and `journalctl` implementation under the common `ServiceManager` interface.
- Preserve installed vs loaded units, partial inventory warnings, bounded logs, validated `.service` names and explicit boot enablement semantics.
- Preserve restricted system privilege routing. Application-owned generated units must be directed to the declarative coordinator once Applications exists.
- Compare outputs and behavior against original Go tests and native systemd environments.

### Step 6 — Linux monitoring and package updates

- Port bounded Linux resource/process histories, metrics and dashboard widgets with isolated refresh/error handling.
- Port distribution-aware package status/refresh/install for apt, dnf, pacman, zypper, with exact validated operations, job locks, privilege checks, reboot evidence and read-only cached queries.
- Preserve router `opkg`/self-upgrade behavior as separate platform operations; do not confuse router-specific binary upgrades with Linux OS updates.

### Step 7 — Applications declarative foundation (no provider shortcut)

- Port typed workload YAML `version: 1`, validation (duplicate keys, custom tags, refs, dependency cycles, identity rules), revision-checked owner-only store, exact-byte history and conflict handling.
- Preserve one authoritative YAML for managed workloads, storage/bindings, private file references and shares. Put global host/server settings in the Rust application's config with an explicit migration from the original Server Man `server` stanza; never maintain dual sources of truth.
- Port plan/review/apply, deterministic resource fingerprints/ownership markers, dependency ordering, private journal, preflight/readiness, startup recovery blockers and reviewed revert.
- Port safe command execution, bounded output, durable jobs and privilege separation first. Do not advertise workload creation until underlying mutation/recovery invariants are validated.

### Step 8 — Applications providers, one tab

Port in small, native-tested increments:

1. **Podman Quadlet:** generated owned user definitions, rootless readiness, boot activation.
2. **Podman Compose:** explicit user-scope startup launcher and networking prerequisites.
3. **Docker Compose:** owned definitions, engine/Compose readiness, lifecycle and independent boot policy.
4. **KVM/libvirt:** existing-disk profiles, stable UUID/ownership, persistent definitions, current state and native autostart.
5. **Incus VM:** local project/profile semantics, stopped-guest edits, runtime/boot separation and safe handling of native-owned resources.

All providers appear in **one Applications tab** with type/backend filters and typed editors; no provider-specific top-level tab. Preserve start/stop distinct from enable/disable, partially running group diagnostics, logs, configuration-drift/status separation, and conservative refusal on unverified native ownership.

### Step 9 — Storage provisioning, Samba/NFS shares and configuration health

- Port typed storage/binding prerequisites and explicitly reviewed creation of missing owned directories/disks; do not invent missing data or mount points.
- Port Samba/NFS ownership markers, bounded native inventory, conflict detection, candidate validation, publication/rollback and privilege-helper restrictions.
- Expose a File Sharing tab if enabled; optionally contribute small dashboard health widgets.
- Share model/recovery/preflight infrastructure with Applications rather than creating a second source of configuration truth.

### Step 10 — MCP/agent interface and deferred backup work

- Consider porting Server Man's HTTP/stdio MCP adapters onto the same validated Rust operation registry and auth/write policy; optional and **not** a requirement for completing the first Linux Applications milestone.
- Retain any transferred backup inventory/capture safety checks and recovery blockers, but **do not label existing Server Man `captured` artifacts as restorable backups**. Full backup/restore needs its own native acceptance project and safety gate.
- Retain source/test references to the original Go version until production Linux acceptance is complete.

## Phase 2 acceptance gates

For each migrated capability: contract fixtures compared to Go, unit and integration tests, native Linux guest acceptance where it performs host mutations, permission/privilege tests, failure rollback, restart/boot persistence, and UI tests. Ubuntu is the first deployment target; Debian follows according to available native evidence; Arch is not claimed validated merely because package mappings exist. Keep host-specific tests in disposable VMs or other isolated environments.

The final acceptance matrix must cover:

- Router: unchanged ASP/lightweight UI, APIs, package upgrades, NGINX and security integrations, no Svelte assets.
- Linux: Svelte UI, auth sessions, system/user systemd, monitoring, native package updates, all intended Applications providers, storage/share management and necessary recovery semantics.
- Cross-platform: correct capability discovery, tab/section composition, optional dashboard contributors, and isolation of unsupported modules.
- Release: reproducible build artifacts, platform-specific packaging and migrations, stable versioning and safe update paths.

## Workflow, PRs, and CI discipline

- **Phase 1 branch was for the plan and Phase 1 implementation.** Use small feature-oriented commits; split into reviewable PRs if desired without merging incomplete work into `main`. Draft PRs do not trigger the current CI workflow because `pull_request` is not configured.
- During Steps 1–3, run tests **locally** as needed and record results. GitHub Actions CI stays untriggered on `refactor/modular-architecture`. Do not use auto-CI branch names (`ci/**`) or manual dispatch.
- After Steps 1–3 are complete, request a **manual** CI run for the branch or PR using the existing workflow dispatch. Fix failures before M1 acceptance. No automatic trigger is added.
- Phase 1 was merged and tagged v0.10.5 under Router Hub before this rebrand. A push to `main` normally triggers CI and may trigger auto-version tagging; coordinate version and release policy accordingly.
- The Maestro Phase 1.5 rename is in its own dedicated branch and will require a separate PR and release. Re-run all relevant tests and acceptance.
- Start Phase 2 only after both M1 and M1.5 are accepted. Use separate implementation branches for Linux features/providers.
- The NGINX standalone build (`.github/workflows/build-nginx.yml`) and toolchain-image build remain **manual only**, unrelated to Phase 1 CI policy.
- If workflow triggers are changed in the future, re-audit these assumptions **before pushing**, because branch name alone is not an enforcement control against repository-level automation.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| ASUS menu/ASP stops working after JS modularization | Preserve self-contained rendered body/style/script shape; regression test both standalone and ASUS embedding; test on hardware |
| Router binaries/assets become heavier | Keep embedded renderer, no Svelte/npm in IPK, compare release sizes/RSS against baseline |
| UI hides feature operations | Inventory all existing screens, command handlers, modal flows and deep links; matrix-based browser tests |
| Platform abstraction changes firewall/NGINX semantics | Extract adapters without rewriting operations; stable API and rollback fixtures |
| Existing config/data or upgrade break | Keep paths/schemas through M1; separate versioned rebrand migration with rollback |
| Legacy installed Router Hub IPK collides with Maestro alias | Explicit package conflict, remove old package only after backup, non-destructive config adoption and rollback instructions |
| Go workload port loses transactional safety | Preserve revision, ownership, preflight, journal and review gates; native guest acceptance |
| CI accidentally runs before M1 | Keep branch outside `main`/`ci/**`, no tags or manual dispatch; audit changed workflows |

## Completion checklist

- [ ] B0 baseline/test inventory completed.
- [ ] Phase 1 step 1: backend and UI module contracts implemented.
- [ ] Phase 1 step 2: Rust feature/platform modules reorganized with parity.
- [ ] Phase 1 step 3: ASUS dashboard and tabs modularized, still offline/build-free.
- [ ] M1: local suite and manually initiated CI pass after implementation.
- [ ] M1: ASUS hardware, package upgrade and resource parity accepted.
- [x] Phase 1 release merged/tagged under original name (v0.10.5).
- [x] Phase 1.5: Maestro selected; original `vm75/server-man` untouched as a Phase 2 reference.
- [x] Phase 1.5: source, UI, CLI and package rebrand with controlled migration implemented (GitHub repository rename deferred).
- [ ] M1.5: rebrand compatibility and router deployment validated.
- [ ] Phase 2: Svelte shell + operation registry and Linux auth.
- [ ] Phase 2: systemd Services + monitoring + Linux package updates.
- [ ] Phase 2: declarative coordinator/storage model, provider adapters and Applications UI.
- [ ] Phase 2: Samba/NFS, provisioning and configuration-health integration.
- [ ] Phase 2: Linux native acceptance, router parity and releases completed.
