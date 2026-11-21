# CI and releases

[← Back to README](../README.md)

Maestro follows [Semantic Versioning](https://semver.org/). Set the version
in `Cargo.toml` and commit the matching `Cargo.lock`; Git tags use the
`vMAJOR.MINOR.PATCH` convention (or a prerelease such as `v0.8.0-rc.1`).
The [GitHub Releases page](https://github.com/vm75/router-hub/releases) offers
versioned AArch64 musl tarballs, and for stable tags, `aarch64-3.10`
Entware IPKs. Each artifact has a SHA-256 checksum file.

CI runs automatically on every push to `main`, including PR merges and direct
pushes. Branches named `ci/**`, such as `ci/backup-fix`, also run automatically
on pushes, even without an open PR. Ordinary feature branches and PR events
do not trigger CI.

To check an **open PR manually**, select **Actions → CI → Run workflow**, select
`main`, and enter its PR number. The workflow pins the proposed merge result
against `main` to one commit for both check jobs. Alternatively:

```sh
gh workflow run ci.yml --ref main -f pr_number=123
# Leave the PR number blank to check the selected branch:
gh workflow run ci.yml --ref main
```

Manual runs and `ci/**` branch runs never create release tags. Do not require
automatic PR checks in branch protection if ordinary PRs should remain manual.

## Automatic release tags

After both Rust 1.85 CI and stable compatibility pass for a push to `main`,
the tagging job reads the tested commit's Cargo version and verifies the lockfile
matches. If main has advanced, that older run skips tagging and leaves the decision
to the newer run. A new stable version greater than existing stable tags gets an
annotated `vX.Y.Z` tag on the exact tested commit. Existing version tags are left
untouched, so later merges without a version bump skip publication. Prereleases
and versions with build metadata require manual tags.

The tagging job uses a short-lived GitHub App installation token scoped to this
repository with **Contents: write**. GitHub's built-in `GITHUB_TOKEN` cannot trigger
the tag-push release workflow; an App token can. The token action revokes its token
when the job ends. Only successful automatic main CI can access this tagging job;
PR and opt-in branch checks have no release credentials.

### One-time GitHub App setup

1. Create a GitHub App under your account's **Settings → Developer settings →
   GitHub Apps**. Use the repository URL as its homepage, disable webhooks, and
   restrict installation to your account. No App server or OAuth callback is needed.
2. Set **Repository permissions → Contents → Read and write** and install the App
   on **only Maestro**.
3. In the repository's **Settings → Secrets and variables → Actions → Variables**,
   create `RELEASE_APP_CLIENT_ID` with the App's **Client ID**.
4. Generate a PEM private key in the App's **Credentials → Key pairs** section
   (older layouts use **Private keys → Generate a private key**). Store the entire
   PEM, including its BEGIN/END lines, as the Actions secret
   `RELEASE_APP_PRIVATE_KEY`. Never commit the PEM or paste it into an issue.

See GitHub's [App authentication guide](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow).
Missing credentials fail the tagging job with a setup message only when a new tag
is needed; the CI check jobs still run. After configuring credentials, rerun the
failed tagging job. If main has advanced, use its newer push CI instead.

## Release publication

Pushing a version tag starts a separate full release: version and ancestry
validation, Rust formatting, tests, Clippy, stable toolchain compatibility,
AArch64 musl cross-compilation, tarball/IPK packaging, checksum verification, and GitHub
Release publication. Tags must match Cargo's version and point to commits
already merged into `main`. A prerelease tag publishes a GitHub prerelease.
IPKs are published only for strict stable `vMAJOR.MINOR.PATCH` tags; prerelease
tags continue to publish tarballs only. The IPK builder uses the existing
static musl binary and gzip-tar IPK archives supported by Entware. `maestro upgrade` on a
live Asuswrt-Merlin router verifies the stable IPK checksum before invoking
`opkg install`, or prints the manual command if it cannot install.
No release workflow installs anything onto a router automatically.

CI and release tests install nginx.org stable packages from its signed Ubuntu
repository using the shared setup action. The bundled nginx configuration
requires nginx 1.25.1+ with the HTTP/2 module; the setup checks both before tests.

## Manual NGINX Entware builds and releases

NGINX builds use a **separate, manual-only** workflow in this repository:
[Build Nginx](../.github/workflows/build-nginx.yml). It never runs on a push,
pull request, version tag, or schedule, and it does not install anything on
the router.

After this workflow file is merged to `main` (GitHub requires a workflow to
exist on the default branch for manual dispatch), open **Actions → Build Nginx
→ Run workflow**. Select the version channel: `stable` (default), `mainline`,
or `exact` with an `X.Y.Z` version. Leave the version field blank when using
stable/mainline. The selected branch supplies the build script.

Each successful build uploads a uniquely named, downloadable **Actions
artifact** (retained for 90 days, subject to repository policy) containing the
four matching NGINX IPKs, binary, dynamic modules, checksums, and build info.
The workflow verifies the existing builder's checksums and package versions
before uploading.

By default, the workflow **also creates a separate NGINX GitHub Release** with
the same files. Disable `publish_release` at dispatch to test artifact
creation without publishing a release. Each release has a unique tag such as
`nginx-v1.30.6-run123456789-a1`; repeated builds of the same NGINX version
never overwrite one another. These `nginx-v*` tags cannot trigger the Router
Hub `v*` release workflow. The NGINX release is explicitly marked
`--latest=false`, leaving the existing Maestro release workflow and its
`releases/latest` endpoint (used by `maestro upgrade`) untouched.
On an Asuswrt-Merlin router, `/opt/bin/maestro upgrade-nginx` discovers,
verifies, and installs these published NGINX packages (stable by default;
`--channel mainline` is optional). It distinguishes rebuilds by checking the
installed executable and modules against published checksums, requires
`--allow-downgrade` for version decreases, stages a binary/module recovery
snapshot, and uses the NGINX live binary-upgrade signals instead of an
`S80nginx` stop/restart. See [installation](installation.md#router-only-nginx-upgrade-command)
for failure and rollback limitations.

The builder requires substantial disk space when compiled on a fresh runner.
If the pre-built Entware toolchain container image is available on GitHub
Container Registry (built via `.github/workflows/build-toolchain-image.yml`),
the workflow pulls it and completes NGINX compilation in ~2–3 minutes. If the
image is absent, it compiles the toolchain from source on the host using all
available CPU cores. A successful GitHub build is **not** a router runtime test:
back up the current installation, install NGINX with matching modules, and
verify configuration and startup on the router before switching traffic.

## Publish the next release

1. Update `Cargo.toml` using Semantic Versioning, refresh `Cargo.lock`,
   and update `CHANGELOG.md`. Run local checks and the release build.
2. Merge the version changes into `main` and let automatic main CI pass. With the
   App configured, it creates the stable version tag and starts release publication.
3. For a manual release or prerelease, from the updated `main`, create and push
   an annotated tag after verifying CI:

```sh
git switch main
git pull --ff-only
git tag -a v0.8.1 -m "Maestro v0.8.1"
git push origin v0.8.1
```

Replace `v0.8.1` with the actual new version. Never reuse or move a published
tag; issue a new patch version for corrections. GitHub Actions performs the
release build when the tag is pushed.
