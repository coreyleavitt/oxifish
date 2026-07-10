# RFC 0002 Toolchain sync — handoff

- **Stage:** 2 architect — **BOTH ROUNDS COMPLETE (2026-07-10). RFC at r3. Stage-2 contract satisfied; ready for stage 3.**
- **Resume:** after Corey commits RFC 0001's work (hard precondition — `uv lock --check` is red against the uncommitted tree; slice 3 depends on it) and ideally `/clear`, run: `/loop implement the next unimplemented RFC 0002 slice with /tdd, following the standing rules; after each slice report one progress line; stop when every slice is implemented`
- **Round 2 verdict:** no round-1 reversal overturned (both re-verified adversarially with new evidence: pyo3-introspection structurally inapplicable — function-based pymodule + PyO3 0.27 pin; maturin has no git-tag versioning, so no third version option). One round-1 mechanism FALSIFIED and deepened (enum check), three structural blind spots closed.
- **Context:** the RFC draft PREDATES RFC 0001's landing and stage-4 review; round 1 doubles as the reconciliation pass. Corey chose to run `/architect` directly rather than a separate stage-1 revision (his call, 2026-07-10); the round's fixes should bring the RFC current AND sliced.

## Ground truth the draft is stale against (reviewers briefed on this)
- `python/oxifish/__init__.pyi` DELETED (RFC 0001 stage-4 review); fully-annotated `__init__.py` is the type source; hand-written `python/oxifish/_oxifish.pyi` types the compiled module, gated in CI by `mypy.stubtest` (typecheck job).
- `Mode`/`Padding` StrEnums validated at exactly one Rust site each (`parse_mode`/`parse_padding`, src/key.rs); pytest pins the value sets + case-sensitivity.
- Version still duplicated (Cargo.toml + pyproject.toml, both 0.2.0); release.yml still seds; no agreement check — item 1 stands.
- README rewritten for 0.2.0, examples manually verified but not executed in CI — README item stands.
- Old `pad`/`unpad`/`PaddingStyle` deleted — the draft's "four representations" framing and "426-line stub" facts are stale.
- Item 2/4 (pyo3-stub-gen) possibly moot or a regression vs the hand-written-stub + stubtest steady state — round 1 adjudicates.
- RFC 0001 work is UNCOMMITTED on main (0.2.0 not shipped); recommended-but-declined-for-now: commit 0001 before 0002 implementation starts.

## Slices (r3 — 6; slice 1 is the only Docker rebuild)
- [ ] 1 [D] Enum single-representation + pins (Rust const-table refactor, byte-identical; anchored-regex pins; PER-FILE test-list introspection — STREAM_MODES/cbc-ALL_PADDINGS are exclusions, not list(Enum))
- [ ] 2 [H] Executable docs (three rewrite rules: decrypt-first blocks synthesize ct via encrypt; NONE blocks block-aligned; only fence 1 binds key; per-fence-parametrized tests/test_readme.py; --doctest-modules; README rustup line)
- [ ] 3 [H] Toolchain gates (STEP ZERO: `uv lock --check` — red today; then --locked gates, hypothesis profile, scripts/ ruff+mypy w/ 2 known fixes; releases blocked until slice 6)
- [ ] 4 [H] Dockerfile delete
- [ ] 5 [H] Version + floor checks (pytest tests, not scripts: six-surface floor check w/ self-test; three-way Version() assertion; --reinstall-package oxifish in typecheck)
- [ ] 6 [GHA] Release pipeline repair (SemVer translator all 5+chained branches; 4 write sites; in-pipeline assertion — the [skip ci] fix; lockfile refresh+commit; gh release --target; interpreter list; MANDATORY TestPyPI dry-run)
Order: 1, 2, 3, 4, 5, 6. Deps: 2 before 3 (same ci.yml line); 5 before 6; 3 blocks releases until 6.

## Open forks (awaiting Corey)
- None. Round-2 resolutions were evidence-backed recommendations (veto-able): the enum fix costs the "zero rebuilds" property (r2 claimed zero; r3 has exactly one Docker slice) in exchange for actually delivering the invariant.

## Key decisions (round 2, 2026-07-10)
- **Enum mechanism deepened (round-1 claim falsified by depth lens):** the error message's valid-set is a hand-typed literal in the catch-all — parsing it verified enum↔message, NOT enum↔arms. r3 fix: one const table becomes the parse table AND the message source (arms/message/valid-set cease to be separate things); small Rust refactor, byte-identical output proven by existing exact-string pins. Costs r2's "zero rebuilds" — accepted, it delivers the actual invariant.
- **`[skip ci]` blind spot (found independently by 2 lenses):** the bump commit never triggers ci.yml, so the version assertion must ALSO be a release.yml `prepare-version` step. Syntactically-bad SemVer fails safe (cargo hard-errors — reproduced); the release-side assertion covers valid-but-wrong.
- **Lockfile self-version desync:** `uv version --bump` rewrites uv.lock's own oxifish entry (probed); Cargo.lock same shape; release commits only manifests → slice 3's --locked gates would break main after first release. Fix: prepare-version refreshes+commits both lockfiles (slice 6); releases blocked in the 3→6 window.
- **Translation spec completed:** verified sed chain over the full uv-version output set incl. chained `aN.devM`; `pep440_of` doesn't exist — `packaging.version.Version` parses SemVer-hyphen forms directly (probed equal).
- **Six floor surfaces, not four** (+ mypy python_version, ruff target-version); checks live as pytest tests in tests/, not scripts/ (redundant matrix execution = stated trade-off).
- **Doc-rewrite rules hardened:** random-bytes ciphertext deterministically fails decrypt (probed); NONE needs block-aligned lengths (probed); per-fence parametrized harness for real attribution.
- **Misc adopted:** `gh release create --target` fix; `--reinstall-package oxifish` cache guard; `packaging` explicit dev dep; cargo-audit + SECURITY.md support-matrix → Non-Goals; snapshot-table sentence; failure-messages-must-name-source-and-fix rule; README rustup line; TestPyPI dry-run upgraded to MUST.

## Key decisions (round 1, 2026-07-10)
- **Stub generation (r1 items 2/4) DROPPED** — closed by RFC 0001: 4 symbols / 122-line hand stub / stubtest CI-gated and already caught real defects; pyo3-stub-gen cannot emit the load-bearing `@final`/`@disjoint_base` (workaround disables that stubtest check) and loses Literal precision. Revisit trigger: compiled surface grows to dozens of symbols.
- **Version single-sourcing REVERSED** — pyproject.toml stays truth. Hard evidence: `uv version` errors on `dynamic` version fields (probed live: "We cannot get or set dynamic project versions"); release.yml's whole prepare-version job is `uv version`-based; Cargo has no bump. Instead: normalized (packaging.version) three-way CI assertion + fix the 4 release.yml Cargo.toml writes that currently inject invalid SemVer (`0.2.1a1`, `0.2.0.dev47`) — a latent prerelease-path failure found this round.
- **Live bug absorbed into scope**: release.yml builds 3.10 wheels (below floor) and never 3.14 → change 2.
- **Enum-sync mechanism**: runtime-behavior pytest pair (round-trip every member; parse valid-set from live error string), replacing the r1 draft's Rust-source-scraping script. Real gap confirmed: test lists are hand-enumerated, drift passes CI today.
- **README/doctest**: `--doctest-glob` is a silent no-op on this README (zero `>>>` blocks); mechanism = self-contained blocks (rejected fixture-prelude as a new synced surface) + tests/test_readme.py exec harness + --doctest-modules for docstrings.
- **Dockerfile: delete** (unreferenced, strictly weaker than ci.yml, wrong Python base; keeping-verified costs a CI job for zero added coverage). Design lens's "one executable recipe" satisfied by ci.yml itself.
- **New Non-Goals section** so exclusions are explicit: pyo3-stub-gen, CHANGELOG authoring, MSRV, dev-sandbox Docker recipe, runtime changes.
- RFC restructured around the invariant "every repo self-claim is derived or CI-verified", with a claim/source/check audit table as the Problem section.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
