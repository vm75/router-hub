#!/usr/bin/env python3
"""Tag a new stable Cargo version on the exact main commit that passed CI."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def plan(expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected) or git("rev-parse", "HEAD") != expected:
        raise ValueError("checkout does not match the commit that passed CI")
    with open("Cargo.toml", "rb") as source:
        version = tomllib.load(source)["package"]["version"]
    with open("Cargo.lock", "rb") as source:
        locked = [p["version"] for p in tomllib.load(source)["package"] if p["name"] == "maestro"]
    if locked != [version]:
        raise ValueError("Cargo.toml and Cargo.lock versions do not match")
    if not STABLE.fullmatch(version):
        print("Automatic tagging is limited to stable versions; create prerelease tags manually.")
        return None
    if git("rev-parse", "refs/remotes/origin/main") != expected:
        print("Main has advanced; its newer CI run will decide whether to tag.")
        return None
    tags = git("tag", "--list").splitlines()
    tag = f"v{version}"
    if tag in tags:
        print(f"{tag} already exists; leaving it untouched.")
        return None
    numbers = tuple(map(int, version.split(".")))
    released = [tuple(map(int, t[1:].split("."))) for t in tags if t.startswith("v") and STABLE.fullmatch(t[1:])]
    if released and numbers <= max(released):
        raise ValueError("refusing to automatically release a version below the newest stable tag")
    return tag


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"plan", "tag"}:
        raise ValueError("usage: auto-release.py plan|tag (EXPECTED_SHA must be set)")
    expected = os.environ["EXPECTED_SHA"]
    # Refresh before publishing to handle reruns and another run creating the tag.
    if sys.argv[1] == "tag":
        git("fetch", "origin", "main", "--tags")
    tag = plan(expected)
    if sys.argv[1] == "plan":
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            with Path(output).open("a") as stream:
                stream.write(f"needed={'true' if tag else 'false'}\n")
        if tag:
            print(f"Ready to tag {expected} as {tag} after successful main CI.")
    elif tag:
        git("-c", "user.name=maestro-release[bot]", "-c", "user.email=maestro-release@users.noreply.github.com",
            "tag", "-a", tag, expected, "-m", f"Maestro {tag}")
        # Never force a tag update. The App token is supplied by the runner's
        # gh credential helper, not embedded in a remote URL or command line.
        git("push", "origin", f"refs/tags/{tag}")
        print(f"Published annotated tag {tag} at {expected}.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Automatic release tagging failed: {error}", file=sys.stderr)
        sys.exit(1)
