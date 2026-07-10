# RFC 0001: Twofish session API redesign

> **Scope:** this RFC covers the public API redesign, the generic Rust mode engine that replaces the per-mode copy-paste implementations, and the CFB streaming silent-corruption fix (which falls out of the engine's buffering by construction). Build-toolchain sync (stub generation, version single-sourcing, CI drift checks) is RFC 0002.
>
> **Revision history:**
> r2 (2026-07-08) — architect round 1: one-shot `encrypt`/`decrypt` added; StrEnums; ECB split to `ecb_*` factories; Rust key-hygiene corrected (`Arc<Twofish>` + zeroize features); `DecryptionError` narrowed to the error-string channel; zeros-padding scoped; characterization-first slicing.
> r3 (2026-07-08) — architect round 2: `TwofishSession` rename; `encrypt` overloads (explicit-iv returns bare bytes); Python-facade module structure pinned (`#[pyclass(subclass)]` + `_encrypt_raw`); one-shots contractually route through the engine; per-session zeroization story corrected (non-ECB sessions own independent schedule clones); GIL-release copy-before-release soundness invariant; `extension-module` Cargo fix (pre-existing `cargo test` link blocker); `"ecb"` string rejection; error catalog; honest zeroize-verification deliverable; KDBX fixture process (manual GUI, documented recipe); Hypothesis budget; slices re-split to 17.

## Problem

oxifish is a deliberate 1:1 thin binding over RustCrypto's Twofish primitives, which pushes three composition burdens onto every Python caller:

- **Padding is caller-side.** CBC requires `pad → encrypt` / `decrypt → unpad`, coordinating block size and style across module-level functions and a Python-side `PaddingStyle` enum. Forgetting or mismatching fails at runtime, far from the mistake (`Zeros` can silently lose data).
- **Streaming has no end-of-stream.** `encryptor()`/`decryptor()` objects require 16-byte-aligned chunks; `finalize()` was removed (66d5ca4) to match PyCryptodome, so arbitrary-length streaming is impossible. Worse, **CFB streaming silently corrupts output on non-aligned chunks** — verified: chunks under 16 bytes freeze the feedback register (outright keystream/feedback reuse — a confidentiality bug, not just corruption); larger unaligned chunks derive feedback from a misaligned window. It never raises; it always "succeeds".
- **IV discipline is entirely caller-side.** One-shot APIs take an IV per call on a long-lived key object, inviting IV reuse; nothing marks an IV as consumed.

Internally, the five modes (ECB/CBC/CTR/CFB/OFB) live as near-duplicate implementations in a single 1061-line `src/lib.rs`: 11 `#[pyclass]` types, 9 hand-written `Drop` impls, 6 copies of block-alignment validation, per-object `Vec<u8>` key clones. Precision: the reconstruct-per-call bug affects **CBC and CFB streaming** (full key-schedule re-expansion on every `update()`); CTR/OFB already retain a live cipher object and are structurally sound, just duplicated.

**Pre-existing latent bugs surfaced by review:**
1. No crate in `Cargo.toml` enables the `zeroize` feature (`twofish`'s zeroizing `Drop` is feature-gated, off by default) — the in-code "key material is securely cleared" comments are currently false.
2. `pyo3 = { features = ["extension-module"] }` in `Cargo.toml` makes plain `cargo test` fail to link (extension modules don't link libpython). Wheel builds don't need it there — `pyproject.toml`'s `[tool.maturin] features = ["pyo3/extension-module"]` already enables it for maturin builds. No CI job has ever run `cargo test`, so this was never noticed.
Both fixed in slice 1.

## First-Principles Ideal

A **deep cipher-session module**: a key object constructed once; the dominant use case (whole-message encrypt/decrypt) as a single obvious, safe call; streaming sessions bound to exactly one mode, one IV, and one padding policy, with internal buffering (any chunk size in, remainder buffered, explicit end-of-stream out); misuse (IV reuse within a session, update-after-finalize, unpadded tails) either structurally impossible or a loud error.

What's blocking the ideal is inertia: the PyCryptodome-shape prior (the stated reason for removing `finalize()`) is itself the source of the friction. The package is 0.1.x beta; a clean break is cheap now.

**Design decision (Corey, 2026-07-08): A-hybrid accepted; PyCryptodome-shape compatibility explicitly dropped.** Rounds 1–2 refined the surface; depth is measured by whether the natural call for the dominant case is one safe line, not by raw type count.

## Proposed Interface

Module structure: the Rust extension (`oxifish._oxifish`) exposes `#[pyclass(subclass)]` classes with private raw methods; the thin Python layer (`oxifish/__init__.py`) subclasses/wraps them and owns the enums, `EncryptResult`, and coercions. The public `.pyi` documents only the Python-facing surface.

```python
BLOCK_SIZE: Final[int]                      # 16
Buffer: TypeAlias = bytes | bytearray | memoryview   # collections.abc.Buffer is 3.12+; floor is 3.11

class Mode(StrEnum):                        # Python layer; Rust validates the strings
    CBC = "cbc"; CTR = "ctr"; CFB = "cfb"; OFB = "ofb"    # "ecb" excluded AND rejected as a string — see Contracts

class Padding(StrEnum):
    PKCS7 = "pkcs7"; NONE = "none"; ISO7816 = "iso7816"; ANSIX923 = "ansix923"; ZEROS = "zeros"

class EncryptResult(NamedTuple):            # Python layer
    iv: bytes
    ciphertext: bytes

class DecryptionError(ValueError):
    """Uniform padded-decrypt failure. See Contracts for the normative
    security scope (error-string channel only)."""

class TwofishKey:                            # Python subclass of _oxifish.TwofishKey
    def __init__(self, key: Buffer) -> None: ...          # 16/24/32 bytes; ValueError otherwise
    @property
    def key_size(self) -> int: ...

    # ---- one-shot: the hot path ----
    @overload
    def encrypt(self, data: Buffer, mode: Mode | str = Mode.CBC, *,
                iv: None = None, padding: Padding | str | None = None) -> EncryptResult: ...
    @overload
    def encrypt(self, data: Buffer, mode: Mode | str = Mode.CBC, *,
                iv: Buffer, padding: Padding | str | None = None) -> bytes: ...
    # iv omitted → auto-generated (OS CSPRNG) → EncryptResult(iv, ciphertext): the two
    # values that must travel together. iv supplied → the caller already owns it → bare
    # ciphertext bytes (symmetric with decrypt()).
    # iv parameters accept any Buffer (bytearray/memoryview — the KDBX header-slice
    # idiom), coerced like data; EncryptResult.iv is always bytes. (Widened from
    # bytes-only in stage-4 review, finding 3.)
    def decrypt(self, data: Buffer, mode: Mode | str = Mode.CBC, *,
                iv: Buffer, padding: Padding | str | None = None) -> bytes: ...

    # ---- streaming sessions (single-use) ----
    def encryptor(self, mode: Mode | str = Mode.CBC, *,
                  iv: Buffer | None = None, padding: Padding | str | None = None) -> TwofishSession: ...
    def decryptor(self, mode: Mode | str = Mode.CBC, *,
                  iv: Buffer, padding: Padding | str | None = None) -> TwofishSession: ...

    # ---- ECB: separate, deliberately sharp, padding must be explicit ----
    def ecb_encryptor(self, *, padding: Padding | str) -> TwofishSession: ...
    def ecb_decryptor(self, *, padding: Padding | str) -> TwofishSession:
        """ECB leaks block-level plaintext patterns; use only for single-block
        operations or explicit interop. (Security scope: see Contracts.)"""

class TwofishSession:                        # single-use; obtained via the factories above
    @property
    def mode(self) -> Literal["cbc", "ctr", "cfb", "ofb", "ecb"]: ...   # superset of Mode: ECB sessions report "ecb"
    @property
    def direction(self) -> Literal["encrypt", "decrypt"]: ...
    @property
    def iv(self) -> bytes:
        """The IV in use (auto-generated or caller-supplied); not secret.
        Unconditionally bytes for IV modes; on ECB sessions access raises
        AttributeError at runtime (the descriptor remains visible in dir()/
        stubs — a PyO3 limitation; a separate ECB session type was rejected
        to avoid re-growing the class count). Readable after finalize()."""
    def update(self, data: Buffer) -> bytes:
        """Any chunk size — alignment handled by internal buffering; may
        return b'' while buffering partial blocks. Padded-DECRYPT sessions
        additionally withhold the most recent complete block (it may carry
        padding) until finalize(): N aligned input blocks yield N-1 from
        update(); the last arrives from finalize(). Encrypt sessions and
        padding="none" have no holdback. RuntimeError after finalize()."""
    def finalize(self, data: Buffer = b"") -> bytes:
        """Optional final chunk + flush + apply/verify padding; consumes the
        session (update/finalize barred afterwards; properties stay readable).
        The data parameter is load-bearing: it keeps ECB (which has no
        one-shot) single-expression — key.ecb_encryptor(padding=Padding.NONE)
        .finalize(block) — do not remove it in a cleanup pass."""
    def __repr__(self) -> str: ...          # mode, direction, state, iv — NEVER key material
```

Usage — the KeePass hot path (IV lives in the KDBX header) and streaming:

```python
key = TwofishKey(derived_key)
plaintext = key.decrypt(ciphertext, iv=header_iv)          # PKCS7 default, one line

iv, ciphertext = key.encrypt(plaintext)                     # auto-IV → EncryptResult
ct = key.encrypt(aligned, iv=iv, padding=Padding.NONE)      # explicit IV → bare bytes

enc = key.encryptor(Mode.CFB, iv=iv)                        # streaming: chunks of any size
out = enc.update(a) + enc.update(b) + enc.finalize()

kat = key.ecb_encryptor(padding=Padding.NONE).finalize(block)   # KAT / raw block path
```

### Contracts (normative)

- **Engine unification.** One-shot `encrypt`/`decrypt` MUST be implemented as internal session construction + the same `ingest()`/`close_out()` engine path `update()`/`finalize()` use — never a separate direct RustCrypto one-shot call. This makes chunking invariance a structural guarantee, not a coincidence of two independently correct implementations.
- **Mode/Padding strings** match exactly (case-sensitive, no trimming, no normalization). An unrecognized string raises `ValueError` naming the received value and the full valid set (see Error catalog). **The string `"ecb"` is rejected by `encrypt`/`decrypt`/`encryptor`/`decryptor` exactly like any unknown mode** — ECB is reachable only via `ecb_encryptor`/`ecb_decryptor`. Regression-tested.
- **Padding defaults & rejection.** `padding=None` means PKCS7 for CBC. For stream modes (ctr/cfb/ofb), passing **any** explicit `padding=` value — including `"none"` — raises `ValueError`. ECB factories require explicit `padding=`.
- **`padding="none"`** enforces block alignment **once, at `finalize()`, against the total accumulated length** — never per-`update()` chunk. Misalignment is a caller-side usage error: plain `ValueError` (see catalog), **never** `DecryptionError`. Zero total bytes is valid and symmetric: `b""` in → `b""` out, both directions.
- **Empty-message matrix** (pinned by test, one-shot and streaming): pkcs7/ansix923/iso7816 encrypt of `b""` produce exactly one full padding block; `zeros`/`none` produce `b""`; stream modes produce `b""`.
- **`DecryptionError`** fires only on padded-decrypt failures: invalid padding bytes, or total padded ciphertext shorter than one block (including zero bytes). **This is the canonical statement of its security scope:** one fixed message (see catalog) closing the error-*string* side channel; the padding-byte comparison is branch-free over the full candidate range; **no constant-time claim is made** — Twofish's key-dependent S-boxes are inherently non-constant-time (docstrings and Non-goals reference this bullet rather than restating it). **Not detected:** wrong key, wrong IV, or wrong mode on unpadded data silently yields garbage plaintext — inherent to unauthenticated ciphers.
- **`"zeros"` unpad is scoped to the held-back final block only** (strips 0–15 trailing zeros, matching what padding can produce). Deliberate tightening vs. the old whole-buffer `unpad()`; pinned by a test whose plaintext has a genuine zero run straddling the final block boundary. `zeros` remains ambiguous against plaintext ending in `0x00`; interop-only.
- **CTR `iv`:** the full 16-byte initial counter block, big-endian 128-bit increment (`Ctr128BE`) — **not** a nonce+counter split. README carries a CTR interop example.
- **Input types:** `key`/`data` accept `bytes`, `bytearray`, `memoryview` (read-only buffer protocol).
- **Concurrency & GIL soundness.** Buffer-protocol input is copied into engine-owned memory **while the GIL is held**; the GIL is released (`py.allow_threads`) only around the pure-Rust transform of that owned copy — never while holding a live borrow into caller-supplied memory. This is a soundness requirement (a `bytearray` can be mutated/resized by another thread), not an optimization choice; it must not be relaxed without `PyBuffer` exclusive-access locking. Sessions are single-writer: concurrent `update()`/`finalize()` on one instance raises `RuntimeError` (PyO3 `PyBorrowMutError`), regression-tested with a barrier/retry to avoid flakiness. Free-threaded (`--disable-gil`) CPython builds are untested and not a supported target for this contract.
- **Serialization:** `TwofishKey`/`TwofishSession` are unpicklable and non-copyable; `pickle.dumps`, `copy.copy`, and `copy.deepcopy` all raise `TypeError`, regression-tested.
- **`__repr__`:** `TwofishKey` shows only `key_size`; `TwofishSession` shows mode, direction, session state, and iv. Tested positively (documented fields present) and negatively (no key bytes).

### Error catalog (normative strings)

| Condition | Type | Message |
|---|---|---|
| Padded-decrypt failure (any cause) | `DecryptionError` | `"decryption failed: invalid or corrupted ciphertext"` |
| `padding="none"` misalignment at finalize | `ValueError` | `"data length (N) is not a multiple of the block size (16)"` |
| Unknown mode/padding string (incl. `"ecb"` to the shared factories) | `ValueError` | `"invalid mode '<value>': expected one of 'cbc', 'ctr', 'cfb', 'ofb'"` (analogous for padding) |
| `update`/`finalize` after finalize | `RuntimeError` | `"session is already finalized"` |
| Concurrent access to one session | `RuntimeError` (`PyBorrowMutError`) | PyO3-provided; distinct from the finalized message, documented as such |

All messages regression-tested. (Exact wording is Corey-tunable; the *existence* of one fixed string per row is the contract.)

### What it hides

- *Padding state machine* — implemented **once in the engine**, mode-agnostic, operating on the final block(s) at `finalize()`; mode primitives only transform blocks. This single implementation serves CBC **and** ECB identically (there is no RustCrypto `ecb` crate — ECB block-loops directly on the shared `Arc<Twofish>`; it must NOT grow a second padding path, and CBC must not use `cbc`'s own `encrypt_padded_mut` helpers, which would be that second path). Three buffering disciplines: encrypt flushes complete blocks eagerly (no holdback); padded decrypt always withholds the most recent complete block; `padding="none"` decrypt flushes eagerly and checks alignment at `finalize()`.
- *Chunk buffering vs. live keystream state* — block modes (ECB/CBC, and CFB's feedback register) run through the engine's `pending` partial-block buffer; CTR/OFB need no buffering (`StreamCipherCoreWrapper` tracks mid-block keystream position). Either way, `update()` never hands unaligned data to a primitive incorrectly — eliminating the CFB bug by construction.
- *IV lifecycle* — captured once at construction (or CSPRNG-generated via `getrandom`), exposed read-only, zeroized on drop. Sessions are single-use; accidental IV reuse requires explicitly passing the same `iv` twice.
- *Rust structure (honest version)* — `TwofishKey` holds `Arc<Twofish>` with the **`zeroize` feature enabled** on `twofish`/`cipher`/`cbc`/`cfb-mode`/`ctr`/`ofb` (off today; current zeroization comments are false). **Session key-material lifetimes, precisely:** the RustCrypto mode wrappers (`cbc::Encryptor<C>`, `cfb_mode::Encryptor<C>`, `CtrCore<C,_>`, `OfbCore<C>`) all own their cipher by value — so **every non-ECB session holds its own independent `Twofish::clone()` (exactly 184 bytes of round-key schedule; no raw-key re-derivation) and zeroizes it on that session's own drop.** Only the `Arc<Twofish>` held by `TwofishKey` (and borrowed by ECB sessions) is governed by reference-counted last-drop zeroization. SECURITY.md must state both lifetime models, plus the generic `zeroize` caveat: drop-based zeroization covers the final owning copy; it cannot erase transient stack copies the optimizer may introduce during moves. Raw key bytes are copied zero *additional* times after `__init__`.
- *Engine mechanism (pinned to real crate APIs, verified)* — sessions retain **one live** mode object each: `cbc::Encryptor/Decryptor<Twofish>` driven incrementally via `encrypt_blocks_mut`/`decrypt_blocks_mut` (IV state chains across calls), `cfb_mode::Encryptor/Decryptor` (**not** the self-buffering `Buf*` variants — buffering lives in the engine only), `StreamCipherCoreWrapper` for CTR/OFB, bare `Arc<Twofish>` for ECB. All concrete types are plain `Send` structs — the internal dispatch is an ordinary Rust enum over the eight variants, no trait objects, no `unsendable`. `finalize(data)` = shared `ingest()` + close-out, the same path `update()` and (per Contracts) the one-shots use.

**Deleted:** `TwofishECB/CBC/CTR/CFB/OFB` and their 5 streaming companions, module-level `pad`/`unpad`, `PaddingStyle`/`KeySize`/`BlockSize` enums. `encrypt_block` use cases → `ecb_encryptor(padding=Padding.NONE).finalize(block)`.

### Non-goals

- **AEAD** — callers needing integrity use an outer MAC (as KDBX does).
- **Timing-equalized decrypt paths** — see the `DecryptionError` contract bullet for the canonical scope; equalizing fail-fast length checks against full decrypts is disproportionate for a local-file library on a non-constant-time primitive.
- **Context-manager protocol** — refcounting + `Drop` already zeroize promptly.
- **`__eq__`/`__hash__` on `TwofishKey`**; **KDF helpers**; **internal session locking**; **free-threaded CPython support** (see Concurrency contract).

## Dependency Strategy

**In-process** (category 1) with one named boundary: auto-IV generation via the `getrandom` crate (new dependency). Tested at the Python boundary (uniqueness assertions, not mocks). New dev-dependencies: `static_assertions` (Rust), `pykeepass` (Python `dev` group — test-only oracle, never a runtime or wheel dependency).

## Testing Strategy

**New boundary tests:**
- Official Twofish KATs (128/192/256) via `ecb_encryptor(padding=Padding.NONE)`.
- **KeePass golden vectors:** a KDBX4 fixture (Twofish cipher, known password) created **once, manually, via the KeePassXC GUI** (Database Settings → Security → Encryption Algorithm → Twofish) — `keepassxc-cli db-create` has no cipher-selection flag (upstream keepassxreboot/keepassxc#13282), so this is an out-of-band input produced before the relevant slice, not a slice deliverable. Committed under `tests/fixtures/` with a `README.md` recording the KeePassXC version, exact settings, and password so it is regenerable. Opened via `pykeepass` as the independent oracle, asserting byte-exact plaintext. (PyPI `twofish` cannot oracle the padded path — raw modes only.) *First action of the golden-vector slice: verify pykeepass's KDBX4 Twofish call site is one-shot whole-payload.*
- **Chunking-invariance property (Hypothesis):** for every applicable mode × padding combination (13: CBC/ECB × 5 paddings + 3 stream modes), any random partition of a message through `update()` calls must byte-match the one-shot output. Includes the zeros-straddle case. **Budget:** dedicated strategy `st.binary(max_size=200)`, `@settings(max_examples=25, deadline=None)` per combo; the all-1-byte-chunks case is a small fixed example test per mode (bounded cost), not folded into the random strategy; a Hypothesis CI profile registered in `conftest.py` so local runs can go deeper.
- Round-trip properties across modes/paddings/key sizes; `padding="none"` alignment + `b""` symmetry; empty-message matrix. **Re-homed from the current suite (not dropped):** ECB determinism (same key+block → same ciphertext), cross-mode output differentiation, invalid key/IV-length rejection properties.
- Misuse matrix: post-`finalize()` `RuntimeError`; missing `iv` on non-ECB decrypt; any explicit `padding=` on stream modes (incl. `"none"`); `"ecb"` string to shared factories; bad key/IV lengths; short/empty padded ciphertext → `DecryptionError`; every Error-catalog string regression-tested; two threads racing one session → `RuntimeError` (barrier/retry against flakiness).
- Buffer-protocol inputs end-to-end; pickling **and** `copy.copy`/`copy.deepcopy` raise; reprs tested positively and negatively; `DecryptionError` importable from `oxifish`, in `__all__`, stubbed.
- GIL-release test: a second Python thread demonstrably runs (via `threading.Event`) while a large `encrypt()` is in flight; plus a `bytearray`-mutation-during-encrypt test proving copy-before-release (no crash/corruption).
- Rust-level `cargo test` for the engine — requires the slice-1 Cargo fix (see Problem #2) and a new lean `rust-test` CI job (ubuntu-only, `dtolnay/rust-toolchain` + `cargo test`, no Python needed; add `Swatinem/rust-cache@v2` opportunistically — no caching exists in CI today).
- **Zeroization (honest deliverable):** memory-clearing is not observable without UB, so: compile-time `static_assertions::assert_impl_all!(Twofish, ZeroizeOnDrop)` (fails if the feature wiring breaks); a drop-liveness test (construct/drop key + every session variant, no panic); and a review checklist — every oxifish-owned struct holding key/IV material derives `ZeroizeOnDrop` or manually zeroizes in `Drop`. A structural guarantee, not a behavioral test.
- Perf: benchmark new-engine whole-message throughput vs. current on a 1–10 MB payload; results recorded in the final slice's PR description; **threshold: within 20% of current throughput, or the discrepancy is explicitly called out and accepted before merge** (number Corey-tunable; some threshold must exist).

**Old tests to delete:** per-class one-shot/streaming tests tied to the removed classes; `pad`/`unpad` unit tests. Inventory note: no streaming-alignment-error tests exist today; the one alignment contract is one-shot `test_data_must_be_block_aligned`, whose exact message is locked through the re-route until the old API is deleted.

**Test environment needs:** pytest + Hypothesis + maturin; `pykeepass` in the `dev` dependency group; the KDBX4 fixture; `getrandom`, `static_assertions`, zeroize feature flags.

## Implementation Path

**Owns:** key schedule + zeroization; IV generation/lifecycle; padding (one implementation, engine-level); chunk buffering; mode dispatch; session state.
**Hides:** RustCrypto types, block alignment, holdback, which mode buffers vs. streams.
**Exposes:** construct key; one-shot `encrypt`/`decrypt`; sessions with `update`/`finalize`.

**Module boundary (pinned):** Rust exposes `_oxifish.TwofishKey` (`#[pyclass(subclass)]`) with private `_encrypt_raw`/`_decrypt_raw` returning plain tuples/bytes; the Python layer subclasses it as the public `TwofishKey`, wrapping into `EncryptResult` and coercing `Mode`/`Padding` to strings. `TwofishSession` is returned directly from Rust. Public `.pyi` documents the Python-facing surface only.

**Collateral (slice 16):** SECURITY.md — both zeroization lifetime models + transient-stack-copy caveat + Supported Versions (0.2.x added; 0.1.x EOL, stated); 0.2.0 release body gets an explicit Breaking Changes section with the old→new mapping table; README Python-version reconciliation. Root `Dockerfile` drift → RFC 0002.

## Slices

Each slice leaves build, `cargo test`, `cargo clippy -D warnings`, and pytest green. Slices 3–5 add engine code unreachable from the pymodule: a scoped `#[allow(dead_code)]` is expected until slice 6 wires it up (removed there). The KDBX fixture is produced out-of-band before slice 9.

1. **Truth & plumbing.** Remove `extension-module` from `Cargo.toml`'s pyo3 line (maturin's `[tool.maturin] features` already covers wheel builds; required for `cargo test` to link at all). Enable `zeroize` features on all five RustCrypto deps + `cipher`; add `getrandom`, `static_assertions`; delete/fix the false zeroization comments; add the lean `rust-test` CI job (+ `Swatinem/rust-cache@v2`); `assert_impl_all!(Twofish, ZeroizeOnDrop)` + drop-liveness test.
2. **Characterization tests (old API).** Pin today's behavior: CFB streaming sub-16-byte chunk output (feedback-register freeze) and larger-unaligned output, pinned as-is; CBC streaming `update()` alignment `ValueError`; one-shot alignment message; empty-input asymmetries.
3. **Engine: block-mode encrypt buffering** (Rust-only). Eager flush, `pending` buffer, `Fresh → Streaming → Finalized` state machine.
4. **Engine: block-mode decrypt** (Rust-only). `padding="none"` eager path + alignment-at-finalize; padded one-block holdback (incl. single-block messages); branch-free unpad; zeros scoped to final block; engine-level padding shared by CBC and ECB paths.
5. **Engine: keystream + CFB** (Rust-only). Live retained `cfb_mode::Encryptor/Decryptor` + `StreamCipherCoreWrapper`; Rust chunking-invariance tests across all five modes.
6. **Re-route old API through the engine.** Fresh engine session per old-API `encryptor()`/`decryptor()` call (not per `update()` — strictly better for the two streaming classes that re-expand the key schedule every `update()` today; cost-neutral for one-shots). Characterization tests deliberately flipped where behavior improves (CFB now correct); stale "block-aligned chunks" doc-comments deleted now; `test_data_must_be_block_aligned` message preserved.
7. **New surface: key + module boundary.** `_oxifish.TwofishKey` (`pyclass(subclass)`, `Arc<Twofish>`) + Python-layer `TwofishKey` subclass, `Mode`/`Padding`/`EncryptResult`; construction validation, `key_size`, repr.
8. **One-shot CBC hot path.** `encrypt`/`decrypt` via `_encrypt_raw`/`_decrypt_raw` routed through the engine (Contracts: engine unification); overload semantics (auto-IV → `EncryptResult`; explicit IV → bytes).
9. **KDBX golden vectors.** pykeepass call-pattern verification (first action), fixture + `tests/fixtures/README.md`, byte-exact oracle test.
10. **Remaining modes one-shot + sessions.** ctr/cfb/ofb over the engine; padding-rejection contract; `"ecb"` string rejection.
11. **ECB factories + KATs.** `ecb_encryptor`/`ecb_decryptor` (mandatory padding); KATs re-pointed; `finalize(data)` single-expression idiom test.
12. **Streaming plumbing + buffer protocol.** `update()`/`finalize()` over the engine; buffer-protocol inputs (copy-while-GIL-held).
13. **Auto-IV.** CSPRNG via `getrandom`; `.iv` property incl. post-finalize readability and ECB AttributeError; uniqueness test.
14. **Hypothesis chunking-invariance suite.** Per the stated budget; fixed 1-byte-chunk examples; zeros-straddle case; re-homed determinism/differentiation properties; CI profile in `conftest.py`.
15. **Misuse machine + `DecryptionError` + GIL release.** Error catalog implemented + all strings tested; empty-message matrix; pickle/copy/repr guards; concurrency-race test; GIL release with copy-before-release + the two threading tests.
16. **Port docs, delete old API.** README (CTR note, version fix) + `.pyi`; old classes/`pad`/`unpad`/enums + tests deleted; SECURITY.md + release collateral; version 0.2.0.
17. **Structural cleanup.** Split `src/lib.rs` (`engine.rs`, `session.rs`, `padding.rs`); remove transitional allows; run + record the benchmark against the threshold; clippy/fmt clean.
