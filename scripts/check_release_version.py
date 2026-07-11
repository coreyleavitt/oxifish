#!/usr/bin/env python3
"""In-pipeline version assertion for release.yml's `prepare-version` job.

RFC 0002 (docs/rfcs/0002-toolchain-sync.md), change 1's placement (b):
"as a step inside release.yml's `prepare-version`, right after the
Cargo.toml write". The bump commit release.yml creates is `[skip ci]`, so
ci.yml's `typecheck` job (which runs tests/test_toolchain_sync.py's
equality half) structurally never runs on the one commit this check exists
to guard -- a *valid-but-wrong* SemVer translation would otherwise sail
through `cargo` undetected. This script is the only guard that runs where
it matters.

Standalone (not `tests/test_toolchain_sync.py`) because it must run inside
`prepare-version` without a synced project venv -- the job never builds the
Rust extension, so it is invoked as `uv run --with packaging --no-project
python scripts/check_release_version.py "$VERSION" pyproject.toml
Cargo.toml`, which installs only `packaging` into an ephemeral environment.

Asserts three-way `Version()` equality: the just-bumped `$VERSION`,
`pyproject.toml`'s `[project].version`, and `Cargo.toml`'s
`[package].version` (already SemVer-translated by the sed chain that runs
immediately before this step). `packaging.version.Version` normalizes
SemVer-hyphenated and PEP-440-compact forms of the same version to compare
equal, so no custom translation logic lives here -- only comparison.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from packaging.version import InvalidVersion, Version


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            f"usage: {argv[0]} <bumped-version> <pyproject.toml-path> <Cargo.toml-path>",
            file=sys.stderr,
        )
        return 2

    bumped, pyproject_path, cargo_path = argv[1], Path(argv[2]), Path(argv[3])
    pyproject_version = tomllib.loads(pyproject_path.read_text())["project"]["version"]
    cargo_version = tomllib.loads(cargo_path.read_text())["package"]["version"]

    sources: dict[str, str] = {
        "the bumped $VERSION": bumped,
        str(pyproject_path): pyproject_version,
        str(cargo_path): cargo_version,
    }

    parsed: dict[str, Version] = {}
    for name, value in sources.items():
        try:
            parsed[name] = Version(value)
        except InvalidVersion as exc:
            print(f"FATAL: {name} = {value!r} is not a valid version: {exc}", file=sys.stderr)
            print(
                f"fix: {cargo_path} must hold the SemVer-translated form of the bumped "
                "version (see the sed chain immediately above this step in release.yml)",
                file=sys.stderr,
            )
            return 1

    if len(set(parsed.values())) != 1:
        rendered = {name: str(version) for name, version in parsed.items()}
        print(f"FATAL: version mismatch across sources: {rendered}", file=sys.stderr)
        print(
            f"fix: {pyproject_path} is the source of truth (RFC 0002 change 1) -- sync "
            f"{cargo_path} (via the SemVer translator sed chain above) to match it",
            file=sys.stderr,
        )
        return 1

    print(
        f"version check OK: {bumped} agrees across bumped $VERSION, "
        f"{pyproject_path}, and {cargo_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
