> **Scope:** build/packaging hygiene only — no observable runtime behavior changes (one internal Rust refactor with byte-identical output is included; see change 3). Companion to RFC 0001 (the session-API redesign, landed 2026-07-09; uncommitted at time of writing). Implementation starts after 0001's work is committed — note `uv lock --check` is red against the uncommitted tree today, so slice 3's gates depend on that commit landing first.
>
> **Revision r3 (2026-07-10, architect round 2):** round 2 closed three structural blind spots found by live probing — the version assertion was un-runnable where it mattered (the bump commit is `[skip ci]`), the release flow desyncs the lockfiles' own version entries (which would break the new `--locked` gates after the first release), and the enum check as specified verified the wrong pair (enum↔error-message, not enum↔match-arms; fixed by collapsing arms/message/valid-set into one const table — this RFC's single small Rust slice). Also: complete verified SemVer translation spec, six version-floor surfaces (was four), checks became pytest tests, doc-rewrite rules hardened against two probe-confirmed failure modes.
> **r2 (round 1):** dropped pyo3-stub-gen (closed by 0001); reversed version single-sourcing (pyproject.toml stays truth — `uv version` hard-errors on dynamic fields); absorbed the wheel-matrix bug; added the invariant framing, Non-Goals, and slices.

## Invariant

**Every claim this repo makes about itself is either mechanically derived from one source, or mechanically checked in CI against its source.** Nothing load-bearing is asserted only in a comment, a doc, or a person's memory. Each proposed change is an instance; exclusions are named in Non-Goals. (This audit table is a snapshot at time of writing, not a living artifact — post-implementation, the live enumeration of these checks is the CI job/step list itself, so no synced "living table" is maintained.)

## Problem — claim/check audit (2026-07-10, post-RFC-0001)

| # | Claim | Source of truth | Check today | Status |
|---|-------|-----------------|-------------|--------|
| 1 | Compiled-module types | `python/oxifish/_oxifish.pyi` (hand-written) | `mypy.stubtest` in CI (0001 review) | ✅ closed by RFC 0001 |
| 2 | Facade types | fully-annotated `__init__.py` | `mypy --strict` in CI | ✅ closed by RFC 0001 |
| 3 | Package version | `pyproject.toml` (0.2.0) | none — `Cargo.toml` hand-synced via 4 release.yml write sites (3 `sed` + 1 PowerShell); nothing verifies agreement; prerelease/TestPyPI writes put PEP-440 strings (`0.2.1a1`, `0.2.0.dev47`) into `Cargo.toml` = **invalid SemVer**, a latent cargo/maturin parse failure | ❌ change 1 |
| 4 | Supported Pythons | `requires-python = ">=3.11"` | **six** hand-synced encodings: classifiers, ci.yml matrix, release.yml `--interpreter` list, `[tool.mypy] python_version`, `[tool.ruff] target-version` — and release.yml **builds 3.10 wheels (below floor) and never 3.14** (live bug) | ❌ change 2 |
| 5 | `Mode`/`Padding` value sets | Rust `parse_mode`/`parse_padding` | **three** independently-drifting encodings: the match arms, the hand-typed `"expected one of …"` message literal in the catch-all, and hand-enumerated pytest lists — a new arm or member that misses any sibling passes every gate | ❌ change 3 |
| 6 | README examples | `README.md` (7 python fences) | none; fences use never-defined placeholders — extract-and-run fails, `--doctest-glob` silently collects zero | ❌ change 4 |
| 7 | Docstring examples | `__init__.py` module docstring (`>>>`, same placeholders) | none (probe: `--doctest-modules` collects exactly 1 item, fails at first line) | ❌ change 4 |
| 8 | Dependency resolution | `Cargo.lock` / `uv.lock` (committed; each also carries the package's **own version** as an entry) | CI never passes `--locked`; release.yml's bump **rewrites the manifests but never the lockfiles**, so every release desyncs them | ❌ changes 5+6 |
| 9 | Hypothesis CI budget | conftest's `"ci"` profile | ci.yml never selects it | ❌ change 5 |
| 10 | `scripts/` code quality | project ruff/mypy bar | absent from every CI glob (probe: ruff already clean; mypy --strict has exactly 2 fixable errors) | ❌ change 5 |
| 11 | "How to build/test this repo" | `ci.yml` (executable by definition) | root `Dockerfile` is an unreferenced weaker duplicate; README's Development section installs uv but never Rust | ❌ change 7 |
| 12 | "Releases ship a verified version" | the release pipeline itself | the bump commit is `[skip ci]` — **ci.yml structurally never runs on the one commit the version assertion exists to guard**; and `gh release create` has no `--target`, so the tag can point at a racing later commit | ❌ change 6 |

## Proposed changes

### 1. Version: keep `pyproject.toml` as truth; verify agreement, fix validity

(Reversal of the r1 draft, upheld adversarially in round 2: `uv version` hard-errors on `dynamic` fields — probed; maturin has no git-tag-derived versioning — checked `maturin build --help` v1.14.1; so no third option exists in this toolchain.)

Two distinct properties, previously muddled:
- **Validity (the correctness guard):** once `pyproject.toml` is static truth, `Cargo.toml`'s version has exactly one consumer — `cargo`'s manifest parser, which hard-rejects PEP-440 compact strings (probed: `version = "0.2.1a1"` → `cargo metadata` error). Fix all four release.yml write sites to translate first. The complete, probe-verified input set from `uv version --bump` is `{X.Y.Z, X.Y.ZaN, X.Y.ZbN, X.Y.ZrcN, X.Y.Z.devN}` plus the chained TestPyPI case `X.Y.ZaN.devM`; the verified translation:
  ```bash
  SEMVER=$(echo "$VERSION" | sed -E \
    -e 's/^([0-9]+\.[0-9]+\.[0-9]+)rc([0-9]+)/\1-rc.\2/' \
    -e 's/^([0-9]+\.[0-9]+\.[0-9]+)a([0-9]+)/\1-alpha.\2/' \
    -e 's/^([0-9]+\.[0-9]+\.[0-9]+)b([0-9]+)/\1-beta.\2/' \
    -e 's/\.dev([0-9]+)$/-dev.\1/')
  ```
  (plus the PowerShell equivalent at the Windows write site; stable `X.Y.Z` passes through unchanged). Unit-test the translator over the full input set including the chained case.
- **Equality (the drift guard):** assert `Version(importlib.metadata.version("oxifish")) == Version(pyproject) == Version(Cargo.toml)` using `packaging.version.Version` — which parses SemVer-hyphenated forms directly and normalizes (`Version("0.2.1-alpha.1") == Version("0.2.1a1")`, probed), so **no custom `pep440_of` logic exists**; a malformed Cargo version makes `Version()` raise, which is the desired hard fail. `packaging` becomes an explicit dev-group entry (already transitive via pytest — declared, per this RFC's own invariant, rather than relied on silently).

Placement — twice, because of audit row 12: (a) in ci.yml's `typecheck` job, with `uv sync --dev --reinstall-package oxifish` to foreclose uv build-cache staleness; (b) **as a step inside release.yml's `prepare-version`, right after the Cargo.toml write** — the bump commit is `[skip ci]`, so the ci.yml copy never runs where it matters most (a *valid-but-wrong* translation sails through cargo; only this step catches it).

### 2. Python-floor: reconcile and verify six surfaces

Fix release.yml's `--interpreter 3.10 3.11 3.12 3.13` → `3.11 3.12 3.13 3.14`. Add a check asserting **six** surfaces agree with `requires-python`: trove classifiers, ci.yml test matrix, release.yml interpreter list, `[tool.mypy] python_version`, `[tool.ruff] target-version`. Both workflow reads are single-line literals — anchored-regex parseable (stdlib only; no PyYAML dependency). The check must include a self-test proving it fails loudly (not silently no-ops) if a target line is reformatted out of regex reach.

### 3. Enum sync: collapse to one representation, then pin it

Round 2 falsified the r2 mechanism's central claim: the `"expected one of '…'"` valid-set is a **hand-typed literal in the catch-all arm**, not derived from the match arms — so parsing it verifies enum↔message agreement while a new arm with a stale message stays invisible. Three encodings must become one:

- **Rust (this RFC's only Rust change; internal, byte-identical output):** replace `parse_mode`/`parse_padding`'s literal match with a lookup over a single const table (e.g. `ModeSelector::ALL` paired with `as_str()`), and build the error message by joining that same table in catalog order. Arms, valid-set, and message can no longer drift independently because they cease to be separate things. The existing exact-error-string pytest pins prove the output is byte-identical.
- **Pytest pins:** (a) parametrize over `list(Mode)`/`list(Padding)` — every member round-trips through a real call; (b) parse the live message with the anchored contract (naive all-quotes extraction sweeps in the probe's own bogus value and can never pass — probed):
  ```python
  m = re.search(r"expected one of (.+)$", str(exc_info.value))
  valid = set(re.findall(r"'([^']+)'", m.group(1)))
  assert valid == {member.value for member in Mode}
  ```
- **Test-list introspection is per-file, not blanket** (probe-confirmed break otherwise): `ALL_MODES` → `list(Mode)`; `STREAM_MODES` → `[m for m in Mode if m != Mode.CBC]` (it's an exclusion, load-bearing for padding-rejection tests); `test_ecb.py`'s `ALL_PADDINGS` → `list(Padding)`; `test_one_shot_cbc.py`'s `ALL_PADDINGS` → `[p for p in Padding if p != Padding.NONE]` (its round-trip plaintext is deliberately unaligned).

### 4. Executable docs (README + docstrings)

Precondition — rewrite fences and docstring examples to be self-contained, under three probe-derived rules (naive "define the placeholders" fails): (i) a block whose ciphertext is first used by `decrypt()` must synthesize it via a real `encrypt()` in the same block (random bytes are essentially never valid padded ciphertext — probed `DecryptionError`; a comment notes real usage sources it from the KDBX file, and the reader can't tell the difference); (ii) `Padding.NONE` blocks must use exact block-multiple lengths (probed `ValueError` at 31 bytes); (iii) only the first fence binds `key` — later fences reuse, never rebind (a rebound key size would poison everything downstream). "Copy-paste-runnable" holds for the document read in order; individual mid-document fences intentionally depend on earlier ones.

Harness: `tests/test_readme.py`, **parametrized per fence** (fence *i* re-executes fences 0…i) so a failure names its block — the attribution that motivated choosing pytest, made real rather than assumed. Extract ` ```python ` fences only (the ` ```bash ` Development block would otherwise recursively re-invoke pytest). No output matching (auto-IV nondeterminism is structurally moot). Docstrings: `pytest --doctest-modules python/oxifish` (probed: collects exactly the module docstring, touches neither the `.so` nor the `.pyi`; examples carry no expected output, so semantics = executes-without-error).

### 5. Toolchain gates

- **Step zero (probe-confirmed red today):** `uv lock --check` currently fails against the uncommitted 0001 tree — run it first, refresh via lockfile-only `uv lock` if needed, *then* add gates: `uv sync --locked`, `cargo test --locked`, `cargo clippy --locked` (verified: `--locked` = fail-on-drift, the correct flag vs `--frozen`'s silent skip; no interaction with the Swatinem cache).
- `--hypothesis-profile=ci` on ci.yml's pytest line (probed green now, 474 tests). Note: change 4's `--doctest-modules` edits the **same ci.yml line** — sequence slice 2 before slice 3 or merge the edits consciously.
- `scripts/` into the ruff globs (probed: already clean) **and** mypy --strict with exactly two known fixes: annotate `timed(fn: Callable[[], None], …)` and `# type: ignore[attr-defined]` on benchmark.py's old-API `TwofishCBC` import (that symbol exists only in the 0.1.x baseline venv the script's docstring describes).
- **Sequencing constraint:** after this slice lands, cutting a release before change 6 lands would break these gates on main (see row 8) — releases are blocked in that window.

### 6. Release pipeline repair

All release.yml changes, batched (single blast radius, single dry-run): the four SemVer-translated writes (change 1); the interpreter-list fix (change 2); the in-pipeline version assertion (change 1's placement (b)); **refresh and commit `uv.lock` + `Cargo.lock` in `prepare-version` alongside the manifests** — `uv version --bump` rewrites uv.lock's own `oxifish` entry (probed) and Cargo.lock carries the same self-entry, so the current manifest-only commit desyncs both on every release, detonating change 5's gates on the next main push; `--target ${{ needs.prepare-version.outputs.commit_sha }}` on both `gh release create` branches (default is branch-HEAD-at-invocation — a racing push mis-tags the release). GHA-only proof is narrower than r2 claimed: the translator and the `uv version` branch contract are locally provable via a scratch `--project` copy; only the `gh api` tree-commit mechanics and wheel builds need GHA. **A TestPyPI `workflow_dispatch` dry-run is a MUST before the next real release**, not a recommendation. Known pre-existing quirk (out of scope, don't be surprised): `uv version --bump alpha` alone on a stable base errors/no-ops — prerelease bumps are only reachable combined with patch/minor/major.

### 7. Delete the root `Dockerfile`; close the contributor gap it papers over

Unreferenced (grep-confirmed), strictly weaker than ci.yml, wrong Python base. With it gone, README's Development section — which installs uv but only *asserts* "Requires Rust" — gains one rustup install line (parity with the uv line). The opensuse/tumbleweed sandbox recipe in 0001's handoff stays session tooling (Non-Goals).

## Non-goals

- **pyo3-stub-gen adoption** — closed by RFC 0001 (4 symbols, 122-line hand stub, stubtest CI-gated, already caught real defects). Round 2 re-checked adversarially: PyO3's newer first-party introspection stub-gen requires an inline-module declaration (ours is function-based) + PyO3 ≥0.28 (we pin 0.27) — structurally inapplicable. Revisit trigger unchanged: compiled surface grows to dozens of symbols (and note 0001's architecture pushes new API into Python enum values over existing `_raw` methods, i.e. *away* from compiled-surface growth).
- **CHANGELOG.md / release-note authoring** — authored content, not derived/verified. Same reasoning covers **SECURITY.md's Supported-Versions table** (hand-authored policy; revisit if it ever drifts embarrassingly).
- **MSRV declaration** — crate unpublished, wheels prebuilt, CI deliberately floats stable.
- **cargo-audit job** — vulnerability scanning against a live advisory feed is a different concern from claim/check drift; left as-is (its tool version and advisory DB are deliberately unpinned).
- **The dev-sandbox Docker recipe** in handoff docs — session tooling, not a repo claim.
- **Runtime behavior changes** — none; change 3's Rust refactor is proven byte-identical by the existing exact-string pins.

## Dependency strategy

**Local-substitutable (build tooling).** New dev-group entry: `packaging` (already transitive; declared explicitly per the invariant). All checks are pytest tests in `tests/` (not `scripts/`) wrapping pure functions — no new CI wiring, unit-testable without builds; they run redundantly across the 4-version matrix, a stated and accepted trade-off (sub-millisecond text parses; markers not worth the wiring). **One Rust slice** (change 3) needs one Docker rebuild session; everything else is host-only.

## Testing strategy

- Every new check must be demonstrated to **fail on a deliberately broken input** before its pass is trusted: bogus enum member (change 3), typo'd fence (change 4), desynced scratch version (change 1), reformatted matrix line (change 2's self-test), manifest-vs-lockfile mismatch (change 5).
- **Every check's failure message must name the two sources being compared and the fix action** (which file to edit) — a check that fails cryptically gets deleted; red CI must be self-diagnosing without reading this RFC.
- Workflow edits get local fallback proofs (ad-hoc YAML parse via `uvx --with pyyaml` — a proof aid, *not* a project dependency) plus the mandatory TestPyPI dry-run (change 6).

## Slices

1. **[D] Enum single-representation + pins** (change 3): Rust const-table refactor (byte-identical, proven by existing pins) + the two pytest pin families + per-file test-list introspection. The one Docker rebuild. Prove: bogus member fails; scratch stale-message simulation fails the anchored parse; full suite green.
2. **[H] Executable docs** (change 4): README/docstring self-containment under the three rules + per-fence-parametrized `tests/test_readme.py` + `--doctest-modules` wiring + README's rustup line (change 7's doc half). Bundled deliberately: harness without rewrite is always-red; rewrite without harness is unverified.
3. **[H] Toolchain gates** (change 5): `uv lock --check` first (red today), then the `--locked` gates, hypothesis profile, `scripts/` ruff+mypy (two known fixes). Releases blocked until slice 5.
4. **[H] Dockerfile delete** (change 7): trivial, grep-confirmed unreferenced.
5. **[H] Version + floor checks** (changes 1-equality, 2): `tests/test_toolchain_sync.py` pure-function pytest tests (six-surface floor check with self-test; three-way normalized version assertion) + the `typecheck` job's `--reinstall-package oxifish` wiring.
6. **[GHA] Release pipeline repair** (changes 1-validity, 2-list, 6): translator + unit tests over the full input set incl. chained `aN.devM`; four write sites; in-pipeline assertion; lockfile refresh+commit; `--target`; interpreter list. Local proofs as scoped in change 6; then the mandatory TestPyPI dry-run. Last, after 5's checks exist to catch its mistakes.

Dependencies: 2 before 3 (same ci.yml pytest line); 5 before 6; 3 blocks releases until 6. Recommended order: **1, 2, 3, 4, 5, 6.**
