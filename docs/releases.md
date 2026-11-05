# CI and releases

[← Back to README](../README.md)

Router Hub follows [Semantic Versioning](https://semver.org/). Set the version
in `Cargo.toml` and commit the matching `Cargo.lock`; Git tags use the
`vMAJOR.MINOR.PATCH` convention (or a prerelease such as `v0.8.0-rc.1`).
The [GitHub Releases page](https://github.com/vm75/router-hub/releases) offers
versioned AArch64 musl installation archives and SHA-256 checksums.

Automatic CI runs **only after a pull request is merged into `main`**.
Ordinary branch pushes, direct pushes to `main`, and PR updates do not trigger
CI. To check an **open PR manually**, after this workflow has been merged into
`main`, select **Actions → CI → Run workflow**, select `main`, and enter
the PR number. It checks GitHub's proposed merge result against `main`.
Alternatively, run `gh workflow run ci.yml --ref main -f pr_number=123`.
The manual check is not a required pre-merge check; enable a separate
pre-merge workflow if your branch protection needs one.

Pushing a version tag starts a separate full release: version and ancestry
validation, Rust formatting, tests, Clippy, stable toolchain compatibility,
AArch64 musl cross-compilation, packaging, checksum verification, and GitHub
Release publication. Tags must match Cargo's version and point to commits
already merged into `main`. A prerelease tag publishes a GitHub prerelease.
No release workflow installs anything onto a router automatically.


## Publish the next release

1. Update `Cargo.toml` using Semantic Versioning, refresh `Cargo.lock`,
   and update `CHANGELOG.md`. Run local checks and the release build.
2. Merge the version changes into `main` by PR and verify the merged-PR CI.
3. From the updated `main`, create and push an annotated tag:

```sh
git switch main
git pull --ff-only
git tag -a v0.8.0 -m "Router Hub v0.8.0"
git push origin v0.8.0
```

Replace `v0.8.0` with the actual new version. Never reuse or move a published
tag; issue a new patch version for corrections. GitHub Actions performs the
release build when the tag is pushed.
