"""RFC 0002 change 1 (equality half) + change 2: version and Python-floor
drift guards.

RFC 0002 (docs/rfcs/0002-toolchain-sync.md), audit rows 3/4 / Slice 5
("Version + floor checks"). Two independent claims this repo makes about
itself, both previously unchecked:

1. **Version equality** (audit row 3): `pyproject.toml`'s `[project]
   version`, `Cargo.toml`'s `[package] version`, and the version the
   installed package actually reports via `importlib.metadata` must all
   agree. `pyproject.toml` is the source of truth (round-2 reversal,
   RFC section 1); `Cargo.toml` is hand-synced today with no check.
   `packaging.version.Version` parses SemVer-hyphenated forms directly
   and normalizes them against PEP 440 compact forms (`Version("0.2.1
   -alpha.1") == Version("0.2.1a1")`, probed in the RFC), so no custom
   translation logic is needed here -- only comparison. A malformed
   `Cargo.toml` version makes `Version()` raise, which is treated as the
   desired hard fail (validity is change 1's *other* half, released in
   slice 6; this module only asserts agreement, never rewrites either
   file).

2. **Python-floor agreement** (audit row 4): `requires-python =
   ">=3.11"` is hand-duplicated across five other surfaces (trove
   classifiers, ci.yml's test matrix, release.yml's `--interpreter`
   list, `[tool.mypy] python_version`, `[tool.ruff] target-version`).
   The two workflow-file surfaces are single-line YAML literals, parsed
   here with anchored regexes (stdlib `re` only -- no PyYAML dependency,
   per the RFC). Per the RFC's testing-strategy mandate, every such
   parser must fail *loudly* (raise, naming the file and the expected
   line shape) rather than silently return an empty/wrong match when a
   target line is reformatted out of its regex's reach -- pinned below
   by `TestCiMatrixParserSelfTest` / `TestReleaseInterpreterParserSelfTest`.

   release.yml's interpreter list was `3.10 3.11 3.12 3.13` as of slice
   5 -- below the 3.11 floor and missing 3.14 (the RFC's "known live
   bug", audit row 4). RFC 0002 slice 6 fixed it (`--interpreter 3.11
   3.12 3.13 3.14`); `TestReleaseInterpreterFloor` is a hard pass now
   (its `xfail(strict=True, ...)` marker, which proved the check could
   detect the bug, was removed once the fix landed -- an XPASS would
   otherwise have failed the suite, by design).

RFC 0002 slice 6 also added change 1's *validity* half here: release.yml
translates `uv version --short`'s PEP-440-compact output (`0.2.1a1`,
`0.2.0.dev47`) to Cargo-valid SemVer at 4 write sites (3 bash `sed` + 1
PowerShell `-replace`) before writing `Cargo.toml`, because cargo hard-
rejects PEP-440 compact strings. `TestReleaseSemverTranslator` and
friends below extract the sed chain from release.yml's own text (same
loud-failure-on-reformat discipline as the floor-check parsers) and re-run
it via `subprocess` over the full verified input set, so release.yml stays
the single source of truth -- no duplicated chain lives in this file.
"""

from __future__ import annotations

import importlib.metadata
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).parent.parent
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
CI_YML = REPO_ROOT / ".github/workflows/ci.yml"
RELEASE_YML = REPO_ROOT / ".github/workflows/release.yml"

# Declared reference point for the "exactly the supported range" half of
# the floor check (RFC: "derive the expected set from requires-python + a
# single declared LATEST constant in the test"). Bump this alongside any
# future requires-python floor bump.
LATEST_SUPPORTED = "3.14"


# ---------------------------------------------------------------------------
# Change 1 (equality half): three-way version agreement
# ---------------------------------------------------------------------------


def _pyproject_version(pyproject_toml_text: str) -> str:
    """Parse `[project].version` out of pyproject.toml text."""
    return tomllib.loads(pyproject_toml_text)["project"]["version"]  # type: ignore[no-any-return]


def _cargo_version(cargo_toml_text: str) -> str:
    """Parse `[package].version` out of Cargo.toml text."""
    return tomllib.loads(cargo_toml_text)["package"]["version"]  # type: ignore[no-any-return]


def _assert_versions_equal(
    installed: str,
    pyproject_version: str,
    cargo_version: str,
    *,
    pyproject_path: Path,
    cargo_path: Path,
) -> None:
    """Assert `Version(installed) == Version(pyproject_version) ==
    Version(cargo_version)`, using `packaging.version.Version` so
    SemVer-hyphenated and PEP-440-compact forms of the same version
    compare equal with no custom translation logic (RFC 0002 change 1).

    Every failure mode names both files being compared and the fix
    action, per the RFC's testing-strategy mandate ("every check's
    failure message must name the two sources being compared and the fix
    action").
    """
    try:
        installed_v = Version(installed)
        pyproject_v = Version(pyproject_version)
        cargo_v = Version(cargo_version)
    except InvalidVersion as exc:
        raise AssertionError(
            f"could not parse a version being compared across "
            f"importlib.metadata ({installed!r}), {pyproject_path} "
            f"([project].version = {pyproject_version!r}), and {cargo_path} "
            f"([package].version = {cargo_version!r}): {exc} -- fix whichever "
            f"of {pyproject_path} or {cargo_path} holds the malformed "
            "version string (pyproject.toml is the source of truth; sync "
            "Cargo.toml's [package].version to match it)"
        ) from exc

    assert installed_v == pyproject_v == cargo_v, (
        f"version mismatch: importlib.metadata reports {installed_v}, "
        f"{pyproject_path} declares [project].version = {pyproject_v}, "
        f"{cargo_path} declares [package].version = {cargo_v} -- "
        f"pyproject.toml is the source of truth (RFC 0002 change 1); sync "
        f"{cargo_path}'s [package].version to match {pyproject_path}'s "
        "[project].version (and reinstall the package if importlib.metadata "
        "is the odd one out -- that indicates a stale build)"
    )


class TestVersionEquality:
    """The real, currently-checked-in files agree three ways."""

    def test_installed_pyproject_cargo_versions_agree(self) -> None:
        installed = importlib.metadata.version("oxifish")
        pyproject_version = _pyproject_version(PYPROJECT_TOML.read_text())
        cargo_version = _cargo_version(CARGO_TOML.read_text())
        _assert_versions_equal(
            installed,
            pyproject_version,
            cargo_version,
            pyproject_path=PYPROJECT_TOML,
            cargo_path=CARGO_TOML,
        )


class TestVersionEqualityFailsFirst:
    """Fail-first proofs, kept permanently (not scratch tests deleted after
    manual verification): scratch-copy `pyproject.toml`/`Cargo.toml` pairs
    with a deliberately desynced or malformed version, fed to the pure
    `_assert_versions_equal` function -- never the real repo files."""

    def test_desynced_cargo_version_fails_loudly(self, tmp_path: Path) -> None:
        pyproject_scratch = tmp_path / "pyproject.toml"
        cargo_scratch = tmp_path / "Cargo.toml"
        pyproject_scratch.write_text('[project]\nname = "scratch"\nversion = "0.2.0"\n')
        cargo_scratch.write_text('[package]\nname = "scratch"\nversion = "0.2.1"\n')

        with pytest.raises(AssertionError, match=r"version mismatch") as exc_info:
            _assert_versions_equal(
                "0.2.0",
                _pyproject_version(pyproject_scratch.read_text()),
                _cargo_version(cargo_scratch.read_text()),
                pyproject_path=pyproject_scratch,
                cargo_path=cargo_scratch,
            )
        message = str(exc_info.value)
        assert str(pyproject_scratch) in message
        assert str(cargo_scratch) in message

    def test_malformed_cargo_version_fails_loudly(self, tmp_path: Path) -> None:
        pyproject_scratch = tmp_path / "pyproject.toml"
        cargo_scratch = tmp_path / "Cargo.toml"
        pyproject_scratch.write_text('[project]\nname = "scratch"\nversion = "0.2.0"\n')
        # Not valid PEP 440 or SemVer -- Version() must raise, not silently
        # treat it as "less than everything" or similar.
        cargo_scratch.write_text('[package]\nname = "scratch"\nversion = "not-a-version"\n')

        with pytest.raises(AssertionError, match=r"could not parse") as exc_info:
            _assert_versions_equal(
                "0.2.0",
                _pyproject_version(pyproject_scratch.read_text()),
                _cargo_version(cargo_scratch.read_text()),
                pyproject_path=pyproject_scratch,
                cargo_path=cargo_scratch,
            )
        message = str(exc_info.value)
        assert str(pyproject_scratch) in message
        assert str(cargo_scratch) in message

    def test_semver_hyphenated_and_pep440_compact_forms_agree(self, tmp_path: Path) -> None:
        """The RFC's central claim: no custom translation logic is needed
        because `Version()` normalizes both forms itself."""
        pyproject_scratch = tmp_path / "pyproject.toml"
        cargo_scratch = tmp_path / "Cargo.toml"
        pyproject_scratch.write_text('[project]\nname = "scratch"\nversion = "0.2.1a1"\n')
        cargo_scratch.write_text('[package]\nname = "scratch"\nversion = "0.2.1-alpha.1"\n')

        # Must not raise.
        _assert_versions_equal(
            "0.2.1a1",
            _pyproject_version(pyproject_scratch.read_text()),
            _cargo_version(cargo_scratch.read_text()),
            pyproject_path=pyproject_scratch,
            cargo_path=cargo_scratch,
        )


# ---------------------------------------------------------------------------
# Change 2: six-surface Python-floor agreement
# ---------------------------------------------------------------------------


def _requires_python_floor(pyproject_toml_text: str) -> str:
    """Parse the `X.Y` floor out of `requires-python = ">=X.Y"`."""
    requires_python = tomllib.loads(pyproject_toml_text)["project"]["requires-python"]
    match = re.match(r"^>=(\d+\.\d+)$", requires_python)
    if match is None:
        raise ValueError(
            f"pyproject.toml's [project] requires-python = {requires_python!r} "
            "is not in the expected '>=X.Y' shape -- fix pyproject.toml's "
            "requires-python (or update this parser's regex in "
            "tests/test_toolchain_sync.py if the reformat was intentional)"
        )
    return match.group(1)


def _expected_supported_versions(floor: str, latest: str) -> list[str]:
    """The exact `[floor, latest]` inclusive minor-version range, same
    major version, as `["X.floor", ..., "X.latest"]`."""
    floor_major, floor_minor = (int(part) for part in floor.split("."))
    latest_major, latest_minor = (int(part) for part in latest.split("."))
    if floor_major != latest_major:
        raise ValueError(
            f"floor {floor!r} and LATEST_SUPPORTED {latest!r} have "
            "different major versions -- _expected_supported_versions "
            "assumes a single-major-version range; update it if that's no "
            "longer true"
        )
    return [f"{floor_major}.{minor}" for minor in range(floor_minor, latest_minor + 1)]


def _parse_classifier_versions(pyproject_toml_text: str) -> set[str]:
    """Parse `X.Y` versions out of pyproject.toml's trove classifiers
    (`"Programming Language :: Python :: X.Y"`; the bare-major
    `"Programming Language :: Python :: 3"` classifier is intentionally
    excluded -- it has no minor version to compare)."""
    classifiers = tomllib.loads(pyproject_toml_text)["project"]["classifiers"]
    return {
        match.group(1)
        for classifier in classifiers
        if (match := re.match(r"^Programming Language :: Python :: (\d+\.\d+)$", classifier))
    }


def _parse_mypy_python_version(pyproject_toml_text: str) -> str:
    return tomllib.loads(pyproject_toml_text)["tool"]["mypy"]["python_version"]  # type: ignore[no-any-return]


def _parse_ruff_target_version(pyproject_toml_text: str) -> str:
    """Parse `[tool.ruff] target-version = "pyXYZ"` into `"X.YZ"`."""
    target = tomllib.loads(pyproject_toml_text)["tool"]["ruff"]["target-version"]
    match = re.match(r"^py(\d)(\d+)$", target)
    if match is None:
        raise ValueError(
            f"pyproject.toml's [tool.ruff] target-version = {target!r} is "
            "not in the expected 'pyXYZ' shape -- fix pyproject.toml (or "
            "update this parser's regex in tests/test_toolchain_sync.py if "
            "the reformat was intentional)"
        )
    return f"{match.group(1)}.{match.group(2)}"


# Anchored, single-line-literal regexes (RFC 0002 change 2: "stdlib only;
# no PyYAML dependency"). Both require the whole target shape to appear on
# one line; a reformat that spreads the value across multiple lines (a
# YAML block sequence, a `>`-folded scalar, ...) will not match, and the
# functions below raise loudly rather than returning an empty/partial
# result -- proven by TestCiMatrixParserSelfTest and
# TestReleaseInterpreterParserSelfTest.
_CI_MATRIX_RE = re.compile(
    r"^[ \t]*python-version:[ \t]*\[[ \t]*"
    r'(?P<versions>"[0-9.]+"(?:[ \t]*,[ \t]*"[0-9.]+")*)'
    r"[ \t]*\][ \t]*$",
    re.MULTILINE,
)

_RELEASE_INTERPRETER_RE = re.compile(
    r"^[ \t]*args:[ \t]*--release --out dist --interpreter[ \t]+"
    r"(?P<versions>[0-9.]+(?:[ \t]+[0-9.]+)*)[ \t]*$",
    re.MULTILINE,
)


def _parse_ci_matrix_versions(ci_yml_text: str) -> list[str]:
    match = _CI_MATRIX_RE.search(ci_yml_text)
    if match is None:
        raise ValueError(
            'ci.yml\'s `python-version: ["3.11", "3.12", ...]` matrix '
            "line was not found in the expected single-line-literal shape "
            "-- fix .github/workflows/ci.yml's test job matrix (or update "
            "_CI_MATRIX_RE in tests/test_toolchain_sync.py if the reformat "
            "was intentional)"
        )
    return re.findall(r'"([0-9.]+)"', match.group("versions"))


def _parse_release_interpreter_versions(release_yml_text: str) -> list[str]:
    match = _RELEASE_INTERPRETER_RE.search(release_yml_text)
    if match is None:
        raise ValueError(
            "release.yml's `args: --release --out dist --interpreter "
            "3.11 3.12 ...` line was not found in the expected "
            "single-line-literal shape -- fix "
            ".github/workflows/release.yml's build-wheels maturin-action "
            "args (or update _RELEASE_INTERPRETER_RE in "
            "tests/test_toolchain_sync.py if the reformat was intentional)"
        )
    return match.group("versions").split()


_FLOOR = _requires_python_floor(PYPROJECT_TOML.read_text())
_EXPECTED_VERSIONS = _expected_supported_versions(_FLOOR, LATEST_SUPPORTED)


class TestRequiresPythonIsTheReferenceFloor:
    """Sanity-check the reference surface itself: it must actually be in
    the '>=X.Y' shape every other surface is compared against."""

    def test_requires_python_matches_declared_floor(self) -> None:
        assert _FLOOR == "3.11", (
            f"pyproject.toml's requires-python floor is {_FLOOR!r}, but "
            "this test module and its six-surface comparisons assume "
            "'3.11' -- if the floor genuinely moved, update pyproject.toml's "
            "five dependent surfaces (classifiers, ci.yml, release.yml, "
            "[tool.mypy] python_version, [tool.ruff] target-version) and "
            "this assertion together"
        )


class TestClassifiersFloor:
    def test_classifiers_match_expected_supported_range(self) -> None:
        actual = _parse_classifier_versions(PYPROJECT_TOML.read_text())
        assert actual == set(_EXPECTED_VERSIONS), (
            f"pyproject.toml's trove classifiers declare Python versions "
            f"{sorted(actual)}, expected exactly {_EXPECTED_VERSIONS} "
            f"(floor {_FLOOR} from requires-python .. LATEST_SUPPORTED "
            f"{LATEST_SUPPORTED}) -- fix pyproject.toml's [project] "
            "classifiers list"
        )


class TestCiMatrixFloor:
    def test_ci_matrix_matches_expected_supported_range(self) -> None:
        actual = _parse_ci_matrix_versions(CI_YML.read_text())
        assert set(actual) == set(_EXPECTED_VERSIONS), (
            f"ci.yml's test job matrix declares Python versions {actual}, "
            f"expected exactly {_EXPECTED_VERSIONS} (floor {_FLOOR} from "
            f"requires-python .. LATEST_SUPPORTED {LATEST_SUPPORTED}) -- "
            "fix .github/workflows/ci.yml's test job's python-version matrix"
        )


class TestReleaseInterpreterFloor:
    def test_release_interpreter_matches_expected_supported_range(self) -> None:
        actual = _parse_release_interpreter_versions(RELEASE_YML.read_text())
        assert set(actual) == set(_EXPECTED_VERSIONS), (
            f"release.yml's build-wheels --interpreter list declares Python "
            f"versions {actual}, expected exactly {_EXPECTED_VERSIONS} "
            f"(floor {_FLOOR} from requires-python .. LATEST_SUPPORTED "
            f"{LATEST_SUPPORTED}) -- fix "
            ".github/workflows/release.yml's build-wheels maturin-action "
            "--interpreter list (RFC 0002 slice 6)"
        )


class TestMypyPythonVersionFloor:
    def test_mypy_python_version_matches_floor(self) -> None:
        actual = _parse_mypy_python_version(PYPROJECT_TOML.read_text())
        assert actual == _FLOOR, (
            f"pyproject.toml's [tool.mypy] python_version = {actual!r}, "
            f"expected {_FLOOR!r} to match requires-python's floor -- fix "
            "pyproject.toml's [tool.mypy] python_version"
        )


class TestRuffTargetVersionFloor:
    def test_ruff_target_version_matches_floor(self) -> None:
        actual = _parse_ruff_target_version(PYPROJECT_TOML.read_text())
        assert actual == _FLOOR, (
            f"pyproject.toml's [tool.ruff] target-version parses to "
            f"{actual!r}, expected {_FLOOR!r} to match requires-python's "
            "floor -- fix pyproject.toml's [tool.ruff] target-version"
        )


# ---------------------------------------------------------------------------
# Change 2's mandate: parsers must fail loudly, never silently no-op, when
# a target line is reformatted out of regex reach.
# ---------------------------------------------------------------------------


class TestCiMatrixParserSelfTest:
    def test_parses_good_literal(self) -> None:
        text = '        python-version: ["3.11", "3.12", "3.13", "3.14"]\n'
        assert _parse_ci_matrix_versions(text) == ["3.11", "3.12", "3.13", "3.14"]

    def test_raises_loudly_on_block_sequence_reformat(self) -> None:
        # A semantically-equivalent YAML block sequence -- valid YAML, but
        # not the single-line-literal shape the regex targets.
        text = 'python-version:\n  - "3.11"\n  - "3.12"\n  - "3.13"\n  - "3.14"\n'
        with pytest.raises(ValueError, match=r"ci\.yml"):
            _parse_ci_matrix_versions(text)

    def test_raises_loudly_rather_than_returning_empty(self) -> None:
        text = "python-version: []\n"
        with pytest.raises(ValueError, match=r"ci\.yml"):
            _parse_ci_matrix_versions(text)
        # Confirm this is a real raise, not e.g. a caught-and-swallowed one
        # that happens to also raise for an unrelated reason: the good
        # literal above must keep parsing, proving the regex isn't simply
        # broken.
        assert _parse_ci_matrix_versions('        python-version: ["3.11"]\n') == ["3.11"]


class TestReleaseInterpreterParserSelfTest:
    def test_parses_good_literal(self) -> None:
        text = "          args: --release --out dist --interpreter 3.10 3.11 3.12 3.13\n"
        assert _parse_release_interpreter_versions(text) == ["3.10", "3.11", "3.12", "3.13"]

    def test_raises_loudly_on_folded_scalar_reformat(self) -> None:
        # A semantically-equivalent YAML folded scalar -- valid YAML, but
        # spreads the interpreter list onto its own line, out of the
        # single-line regex's reach.
        text = (
            "          args: >\n"
            "            --release --out dist --interpreter\n"
            "            3.11 3.12 3.13 3.14\n"
        )
        with pytest.raises(ValueError, match=r"release\.yml"):
            _parse_release_interpreter_versions(text)

    def test_raises_loudly_rather_than_returning_empty(self) -> None:
        text = "          args: --release --out dist --interpreter\n"
        with pytest.raises(ValueError, match=r"release\.yml"):
            _parse_release_interpreter_versions(text)
        assert _parse_release_interpreter_versions(
            "          args: --release --out dist --interpreter 3.11\n"
        ) == ["3.11"]


# ---------------------------------------------------------------------------
# Change 1 (validity half, RFC 0002 slice 6): release.yml's SemVer
# translator, extracted from release.yml's own text and re-run via
# `subprocess` -- release.yml stays the single source of truth; no
# duplicated sed chain lives in this file.
# ---------------------------------------------------------------------------

# Anchored to the exact multi-line shape release.yml writes the chain in:
# `sed -E \` followed by one or more `-e '<program>' \` continuation lines,
# ending with a final `-e '<program>')` that closes the `$(...)` command
# substitution. A reformat that collapses the chain onto one line, changes
# the `-e` quoting style, or drops the trailing `\` continuations will not
# match -- proven loud (not silently empty) by
# TestReleaseSemverTranslatorParserSelfTest below.
_SED_CHAIN_RE = re.compile(
    r"sed -E \\\n"
    r"(?P<lines>(?:[ \t]*-e '[^'\n]*' \\\n)*"
    r"[ \t]*-e '[^'\n]*'\))",
    re.MULTILINE,
)


def _extract_release_semver_sed_args(release_yml_text: str) -> list[str]:
    """Extract the `-e '<sed program>'` arguments of release.yml's first
    SemVer-translation chain."""
    match = _SED_CHAIN_RE.search(release_yml_text)
    if match is None:
        raise ValueError(
            "release.yml's SemVer-translation `sed -E \\` / `-e '...'` "
            "chain was not found in the expected multi-line shape -- fix "
            ".github/workflows/release.yml's translator (or update "
            "_SED_CHAIN_RE in tests/test_toolchain_sync.py if the reformat "
            "was intentional)"
        )
    return re.findall(r"-e '([^']*)'", match.group("lines"))


def _all_release_semver_sed_chains(release_yml_text: str) -> list[list[str]]:
    """Every occurrence of the chain. release.yml carries 3 verbatim
    copies (one per bash write site: prepare-version, build-sdist,
    build-wheels Unix) -- RFC 0002 slice 6 chose "3 verbatim copies with a
    comment pointing at the unit test" over contorting the workflow to
    share one definition across separate jobs/runners. This function lets
    a test hold that choice to its own bargain: the copies must stay
    byte-identical."""
    return [re.findall(r"-e '([^']*)'", lines) for lines in _SED_CHAIN_RE.findall(release_yml_text)]


def _run_sed_chain(sed_args: list[str], version: str) -> str:
    """Pipe `version` through `sed -E -e <arg1> -e <arg2> ...`, the same
    invocation shape release.yml uses."""
    args = ["sed", "-E"]
    for sed_arg in sed_args:
        args += ["-e", sed_arg]
    # args is built from sed programs extracted out of release.yml plus a
    # fixed, hardcoded input-version string -- not untrusted external input.
    result = subprocess.run(  # noqa: S603
        args, input=version, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


# X.Y.Z optionally followed by a SemVer prerelease/build field: a leading
# "-" then dot-separated alphanumeric/hyphen identifiers (covers plain
# alpha/beta/rc/dev translations and the chained "aN.devM" case, whose
# output embeds a second hyphen inside one dot-separated identifier, e.g.
# "1.2.3-alpha.1-dev.5" -- still one SemVer prerelease field).
_SEMVER_SHAPE_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$")

# The RFC's "complete, probe-verified input set from `uv version --bump`"
# plus the chained TestPyPI case.
_TRANSLATOR_INPUT_SET = [
    "1.2.3",
    "1.2.3a1",
    "1.2.3b2",
    "1.2.3rc3",
    "1.2.3.dev47",
    "1.2.3a1.dev5",
]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the sed chain only ever executes on Linux GHA runners "
    "(prepare-version/build-sdist run on ubuntu; build-wheels' Windows leg "
    "uses the PowerShell mirror) -- Windows sed variants mangle -E "
    "backreferences and are not the environment under test; the ubuntu and "
    "macos CI legs enforce this check",
)
class TestReleaseSemverTranslator:
    """release.yml's sed chain translates `uv version --short`'s
    PEP-440-compact output into Cargo-valid SemVer (RFC 0002 change 1's
    validity half: cargo hard-rejects PEP-440 compact strings like
    "0.2.1a1"). Every input in the verified set must produce SemVer-shaped
    output that `packaging.version.Version` normalizes back to the exact
    same version as the input -- the round-trip proof that translation is
    lossless, not just superficially valid."""

    @pytest.mark.parametrize("version", _TRANSLATOR_INPUT_SET)
    def test_translates_to_valid_semver_round_tripping_to_same_version(self, version: str) -> None:
        sed_args = _extract_release_semver_sed_args(RELEASE_YML.read_text())
        translated = _run_sed_chain(sed_args, version)

        assert _SEMVER_SHAPE_RE.match(translated), (
            f"{version!r} translated to {translated!r}, which is not "
            "SemVer-shaped (X.Y.Z or X.Y.Z-<dot-separated identifiers>) -- "
            "fix the sed chain in .github/workflows/release.yml's "
            "prepare-version step (and its 2 verbatim copies in build-sdist "
            "and build-wheels)"
        )
        assert Version(translated) == Version(version), (
            f"{version!r} translated to {translated!r}, which does not "
            f"round-trip to the same version under packaging.version.Version "
            f"({Version(translated)} != {Version(version)}) -- fix the sed "
            "chain in .github/workflows/release.yml's prepare-version step "
            "(and its 2 verbatim copies in build-sdist and build-wheels)"
        )


class TestReleaseSemverTranslatorSitesStaySynced:
    """The 3 verbatim bash copies (RFC 0002 slice 6's deliberate
    "do not contort the workflow" trade-off) must not drift from each
    other, or two of them would translate differently from the one this
    module actually tests."""

    def test_all_three_write_sites_carry_the_identical_chain(self) -> None:
        chains = _all_release_semver_sed_chains(RELEASE_YML.read_text())
        assert len(chains) == 3, (
            f"expected release.yml's SemVer-translation chain to appear at "
            f"exactly 3 bash write sites (prepare-version, build-sdist, "
            f"build-wheels Unix), found {len(chains)} -- fix "
            ".github/workflows/release.yml, or update this test's expected "
            "count in tests/test_toolchain_sync.py if a write site was "
            "added or removed intentionally"
        )
        assert all(chain == chains[0] for chain in chains), (
            f"release.yml's 3 SemVer-translation sed sites have drifted "
            f"from each other: {chains} -- keep prepare-version's, "
            "build-sdist's, and build-wheels's chains byte-identical (RFC "
            "0002 slice 6 chose verbatim copies over factoring them into "
            "one shared step)"
        )


class TestReleaseSemverTranslatorParserSelfTest:
    _GOOD_CHAIN_TEXT = r"""            SEMVER=$(echo "$VERSION" | sed -E \
              -e 's/^([0-9]+\.[0-9]+\.[0-9]+)rc([0-9]+)/\1-rc.\2/' \
              -e 's/^([0-9]+\.[0-9]+\.[0-9]+)a([0-9]+)/\1-alpha.\2/' \
              -e 's/^([0-9]+\.[0-9]+\.[0-9]+)b([0-9]+)/\1-beta.\2/' \
              -e 's/\.dev([0-9]+)$/-dev.\1/')
"""

    def test_parses_good_chain(self) -> None:
        assert _extract_release_semver_sed_args(self._GOOD_CHAIN_TEXT) == [
            r"s/^([0-9]+\.[0-9]+\.[0-9]+)rc([0-9]+)/\1-rc.\2/",
            r"s/^([0-9]+\.[0-9]+\.[0-9]+)a([0-9]+)/\1-alpha.\2/",
            r"s/^([0-9]+\.[0-9]+\.[0-9]+)b([0-9]+)/\1-beta.\2/",
            r"s/\.dev([0-9]+)$/-dev.\1/",
        ]

    def test_raises_loudly_on_missing_chain(self) -> None:
        with pytest.raises(ValueError, match=r"release\.yml"):
            _extract_release_semver_sed_args("no sed chain of any kind here\n")

    def test_raises_loudly_on_single_line_reformat(self) -> None:
        # A semantically-equivalent one-liner -- valid bash, but collapses
        # the `-e` args out of the multi-line-continuation shape the regex
        # targets.
        text = (
            'SEMVER=$(echo "$VERSION" | sed -E '
            r"-e 's/^([0-9]+\.[0-9]+\.[0-9]+)rc([0-9]+)/\1-rc.\2/' "
            r"-e 's/^([0-9]+\.[0-9]+\.[0-9]+)a([0-9]+)/\1-alpha.\2/' "
            r"-e 's/^([0-9]+\.[0-9]+\.[0-9]+)b([0-9]+)/\1-beta.\2/' "
            r"-e 's/\.dev([0-9]+)$/-dev.\1/')"
            "\n"
        )
        with pytest.raises(ValueError, match=r"release\.yml"):
            _extract_release_semver_sed_args(text)
