# RFC 0003: Interop breadth — XTS, CTR variants, migration path

Status: implemented (0.3.0) — 2026-07-21 (r1 2026-07-12; r2 = architect
round 1 fixes; r3 = architect round 2 fixes)

## Problem

oxifish's mission is to be **the maintained Twofish binding for Python** —
every alternative is dead or unusable (landscape survey 2026-07-12: PyPI
`twofish` archived upstream and broken on 3.12+; pycryptodome explicitly
declined Twofish; pyca/cryptography structurally cannot add it, OpenSSL has
never implemented it; the Botan/nettle bindings that do expose it are not
pip-installable; zero new PyPI entrants 2024–2026).

The current surface (RFC 0001) covers the *chaining-mode* slice of legacy
Twofish data: CBC/CTR/CFB/OFB with an IV, plus quarantined ECB. That serves
KDBX and OpenPGP-shaped data. But Twofish's surviving corpus is wider, and
three real interop targets cannot be served today:

1. **XTS disk-encryption volumes** — the largest surviving Twofish corpus
   after KeePass:
   - **VeraCrypt, and TrueCrypt ≥ 5.0** (Feb 2008 onward), use
     **Twofish-XTS** (IEEE 1619 tweakable mode, two independent key halves,
     per-data-unit tweaks). *Scope note:* TrueCrypt 4.1–4.3a volumes use
     LRW and older ones whole-volume CBC — structurally different modes,
     explicitly out of scope (see Non-goals).
   - **dm-crypt/LUKS** `twofish-xts-plain64` — the sector number as a
     little-endian integer tweak, i.e. exactly the encoding proposed here.
     (dm-crypt's `twofish-cbc-essiv:sha256` is *already* servable: the
     caller computes the ESSIV per-sector IV and passes it as an ordinary
     `iv=`. The `xts-essiv` variant's hash-derived tweak is a non-goal.)

   No `Mode` combination reaches XTS today.
2. **Legacy CTR formats with split nonce∥counter layouts** — our CTR is a
   full 128-bit big-endian counter block. No single *named* format demands
   32/64-bit widths (checked: SSH's historical `twofish-ctr` is full
   128-bit; KDBX is CBC-only) — the honest justification is different:
   the dominant convention in the era's homegrown Python code was
   PyCrypto/PyCryptodome's `Counter` with a nonce prefix (a 64-bit or
   32-bit incrementing suffix), and people built Twofish-CTR formats by
   composing the dead `twofish` package with exactly those counters. For
   them, a full-width counter produces diverging keystreams after the
   first counter-block boundary: "my old format almost decrypts" with no
   recourse. Per the Dependency Strategy, serving this is a table row,
   not a design change — cheap insurance for the mission's audience.
3. **Migrants from the dead `twofish` package** — its entire API was
   single-block `encrypt`/`decrypt` (callers built their own modes on
   top). The blessed equivalent already exists
   (`key.ecb_encryptor(padding=Padding.NONE).finalize(block)` — the exact
   idiom RFC 0001's *Deleted* line points to), but it is documented
   nowhere as a migration path. This gap is closed with **documentation,
   not new API** (see §1 below).

Each gap is a case where someone holding real Twofish-encrypted data finds
the ecosystem's only living implementation and still can't read their data
— or can't find the door.

## First-Principles Ideal

The package remains one deep module per cipher construction, each with the
smallest interface that serves its real callers:

- Chaining modes stay exactly as they are (`Mode` + IV + padding).
- XTS is **not a `Mode` member**. `Mode` means "IV-taking chaining mode
  usable with one key via `encrypt`/`encryptor`"; XTS takes a double-length
  key and a tweak, has no IV and no padding (ciphertext stealing instead),
  and is sector-oriented. Forcing it through `Mode` would poison every
  mode-parametrized contract (the enum-introspection machinery from RFC
  0002 would loudly fail the whole suite — that failure mode existing is
  the machinery working). It gets its own construct, mirroring the
  ECB-quarantine precedent: structurally separate, impossible to reach by
  a one-string swap.
- CTR counter width is a *parameter of CTR*, not a new mode: the wire
  format changes but the shape of the operation (IV/initial counter block,
  no padding, streamable) does not.
- **No raw single-block methods on `TwofishKey`.** RFC 0001 deliberately
  deleted `encrypt_block` ("use cases → `ecb_encryptor(padding=
  Padding.NONE).finalize(block)`") on the structural-safety principle this
  RFC itself applies to XTS: a raw primitive must not sit one
  autocomplete-token from the safe path on the same class, mitigated only
  by a docstring — the mitigation strength RFC 0001 already judged
  insufficient. r1 of this RFC proposed re-adding them; r2 reversed that.
  The migration need is real; the answer is documenting the existing
  idiom, which requires zero new API and zero new danger.

## Proposed Interface

### 1. Migration path off the dead `twofish` package (docs only)

No new API. A README section — **"Migrating from the `twofish`
package"** — under the executable-fence rules, showing both shapes the
migrant needs:

```python
# One block (the KAT / known-answer shape):
block_out = key.ecb_encryptor(padding=Padding.NONE).finalize(block_in)

# Many blocks (the real migration shape): ONE session, reused.
# ECB no-padding sessions flush eagerly -- update() returns each block
# immediately -- so a fresh session per block works but wastes a
# construction + FFI crossing per call.
session = key.ecb_encryptor(padding=Padding.NONE)
out = b"".join(session.update(b) for b in blocks) + session.finalize()
```

plus the equivalent `ecb_decryptor` direction, framed exactly as RFC 0001
frames ECB: this is the bare block primitive; composing modes yourself is
almost always a mistake; it exists for known-answer tests and for
mechanical migration. SECURITY.md's ECB Known-Limitations bullet gains a
sentence covering the migration use so the raw-block use case gets the
same documentation strength ECB itself has.

### 2. XTS (`TwofishXTS`)

```python
class TwofishXTS:
    def __init__(self, key: Buffer) -> None: ...
    def encrypt(self, data: Buffer, *, tweak: int) -> bytes: ...
    def decrypt(self, data: Buffer, *, tweak: int) -> bytes: ...
    @property
    def key_size(self) -> int: ...   # TOTAL key bytes: 32, 48, or 64
    def __repr__(self) -> str: ...   # e.g. "<TwofishXTS key_size=64>"
```

- **Single concatenated key**, 32/48/64 bytes: the first half is the data
  key, the second half the tweak key — the ordering IEEE 1619-2007 itself
  defines (Key1 ∥ Key2; Key1 drives the block cipher, Key2 the tweak) and
  every real source follows: VeraCrypt's volume header stores the XTS
  material as one concatenated "master keydata" field (`ks` = primary/
  data, `ks2` = secondary/tweak), dm-crypt/LUKS `twofish-xts-*` takes one
  double-length key, and pyca/cryptography's XTS support uses the same
  convention. A two-argument `(key1, key2)` constructor (considered, r1's
  shape) would force every real caller to pre-split a blob they were
  handed whole and invites a silent argument-swap bug; splitting an
  even-length buffer in half also eliminates the "unequal key lengths"
  error case by construction. KAT tables that list Key1/Key2 separately
  just concatenate: `TwofishXTS(key1 + key2)`.
- `key_size` reports **total** key bytes (32/48/64), matching
  `TwofishKey.key_size`'s total-bytes meaning and pyca's XTS convention
  (`AES.key_size` is the full 512 bits for AES-256-XTS). Overloading the
  name to mean bytes-per-half (r2's shape) would make
  `TwofishXTS(key_size=32)` read as "holds a 32-byte key" when it holds
  64 — r3 corrects this.
- Equal halves (`key[:n] == key[n:]`) are rejected (`ValueError`) — equal
  keys void XTS's CCA-security argument (NIST's 2023 SP 800-38E update
  proposal cites real vulnerabilities from implementations that generated
  identical subkeys) and never occur in real formats. The comparison is a
  plain (non-constant-time) equality: it runs at construction on
  caller-supplied key material, not as a decryption oracle, so
  constant-time treatment buys nothing. **Scoping:** this is a
  construction-time, `TwofishXTS`-facade guard (slice 4) only. The
  generic `src/xts.rs` engine (slice 3) takes two already-built cipher
  instances and must *accept* equal schedules — the official IEEE 1619
  Vector 1 uses Key1 == Key2 (both all-zero) and the engine-level KATs
  need to run it.
- `data` is one **data unit** (IEEE 1619's term). Minimum one block (16
  bytes); maximum 2²⁰ blocks (16 MiB), the IEEE 1619-2007 data-unit
  bound — real formats sit far below it, and enforcing it caps the
  mode's security-bound erosion. Non-block-multiple lengths are handled
  with ciphertext stealing per IEEE 1619, so
  `len(ciphertext) == len(plaintext)` always. *VeraCrypt note:* the data
  unit is **fixed at 512 bytes regardless of the drive's physical sector
  size** (even on 4Kn devices) — the tweak for a byte position is
  `byte_offset // 512`, not the OS's sector number. Docs must say this;
  a wrong unit size is the same silent-garbage failure mode as a wrong
  tweak.
- `tweak` (keyword-only, matching the keyword-only treatment every other
  security-sensitive per-call parameter gets in this API) is the
  data-unit number as an int, encoded little-endian into the 128-bit
  tweak block. Valid range `0 <= tweak < 2**128` (IEEE 1619's full tweak
  space), validated **in the Python facade** so out-of-range values raise
  the cataloged `ValueError` — never PyO3's generic `OverflowError`. A
  non-int `tweak` raises `TypeError` instead (type errors are `TypeError`;
  catalog violations are `ValueError`) — `"tweak must be an int, got
  {type}"`.
  *Interop note:* VeraCrypt and dm-crypt `plain64` only ever present
  tweaks below 2⁶⁴ (a 64-bit sector index, upper tweak bytes zero) — the
  full 128-bit range is IEEE-1619 generality, and tests label the two
  regions accordingly. *Naming note:* pyca's XTS takes `tweak` as the
  raw 16-byte block; ours is the data-unit *number* (what VeraCrypt and
  dm-crypt hand you). Keeping the term-of-art name and documenting the
  int encoding beats inventing a nonstandard parameter name
  (`data_unit`) nobody will search for.
- **The tweak is a position, not a nonce.** Reusing the same tweak when
  rewriting the same data unit is *correct* — that is what a tweakable
  mode is for. The misuse case is the *wrong* tweak for a position (garbage
  plaintext, no error), not a repeated one. Docs must say this explicitly:
  a caller who carries the "never reuse an IV" rule over from the rest of
  this library and randomizes tweaks would silently break interop. The
  README XTS fence is exempt from the IV-reuse guard (it has no IV) and
  the docs state why.
- One-shot only. XTS is random-access by construction (each data unit is
  independent); a streaming session would be a misleading wrapper around a
  loop the caller should own. No padding parameter exists to misuse.
- Zeroization matches RFC 0001 **in full**, not just the key half: both
  expanded key schedules zeroized on drop, *and* the owned copies of
  input data (the GIL-soundness copy, any CTS scratch) zeroized after
  use — the same treatment RFC 0001 gives `Pending`/`HeldBlock`
  plaintext. `__repr__` shows `key_size` and never key material (tested
  positively and negatively, like `TwofishKey`).
- Serialization posture matches RFC 0001's classes: unpicklable and
  non-copyable (`TypeError`), no `__eq__`/`__hash__` beyond identity.
- GIL soundness is restated for this **new** code path, not inherited by
  implication: input buffers are copied to owned memory while the GIL is
  held; the GIL is released only around the pure transform of the owned
  copy (a `bytearray` mutated by another thread mid-call must be unable
  to cause unsoundness — same contract, same test shape as RFC 0001).
- Implementation pattern pinned: the `TwofishKey` two-layer shape
  (`#[pyclass(subclass)]` Rust core + Python facade subclass owning buffer
  coercion, tweak validation, and error catalog), not the
  `TwofishSession` direct-from-Rust shape — the facade work is exactly
  what the Python layer exists for.

**Usage (the primary journey — a VeraCrypt Twofish volume):**

```python
# master_keydata extracted from the volume header: data key || tweak key
xts = TwofishXTS(master_keydata)
data_unit = byte_offset // 512        # VeraCrypt's unit is always 512 bytes
plaintext = xts.decrypt(sector_bytes, tweak=data_unit)
```

### 3. CTR counter width (`ctr_width` keyword)

Exact signatures (kwonly cluster, alongside `iv`/`padding`; `ctr_width`
must appear identically in **both** of `encrypt`/`decrypt`'s existing
overloads or mypy flags overlap):

```python
def encrypt(self, data, mode, *, iv=..., padding=...,
            ctr_width: Literal[32, 64, 128] = 128) -> ...
def decrypt(self, data, mode, *, iv=..., padding=...,
            ctr_width: Literal[32, 64, 128] = 128) -> ...
def encryptor(self, mode, *, iv=..., padding=...,
              ctr_width: Literal[32, 64, 128] = 128) -> TwofishSession
def decryptor(self, mode, *, iv=..., padding=...,
              ctr_width: Literal[32, 64, 128] = 128) -> TwofishSession
```

- `ctr_width` is the number of low-order bits of the initial counter
  block that increment (big-endian) — the NIST-style nonce∥counter split.
  `iv` stays the full 16-byte initial counter block for every width
  (matches RustCrypto's `Ctr32BE`/`Ctr64BE`/`Ctr128BE` 1:1; a caller
  holding a nonce∥counter format concatenates). 128 is today's behavior
  and stays the default; existing ciphertext is unaffected.
- Typed `Literal[32, 64, 128]`, deliberately without the `| str`-style
  escape hatch `mode`/`padding` get: those exist because mode/padding
  strings flow in from config and formats; a counter width is a static
  property of the format the caller is implementing against. A
  dynamically-sourced `int` still validates at runtime via the catalog;
  a `--strict` caller in that rare position casts.
- **Wrap and exhaustion semantics (contract).** The low-N-bit counter
  **wraps through zero** — that is both RustCrypto's `Ctr32BE`/`Ctr64BE`
  behavior (verified in `ctr` 0.10.1 source: the flavor counter is
  relative to session start and wraps) and PyCryptodome `Counter`'s
  documented behavior, i.e. the semantics the motivating legacy formats
  actually produced. What is forbidden is *keystream reuse*: a stream
  ends after exactly `2**N − 1` blocks (one full cycle minus one),
  independent of the IV's initial counter value. Requesting more —
  one-shot, or cumulatively across a session's `update` calls — raises
  the cataloged `ValueError`, never a Rust panic crossing the FFI
  boundary. Implementation is pinned to the crate's fallible path
  (`try_apply_keystream`), which enforces exactly this bound — an
  independent "distance to 2^N" pre-check (r2's framing) would be a
  stricter, non-standard behavior that wrongly rejects legitimate
  wrapping streams. `ctr_width=32` makes exhaustion reachable with real
  data (a 64 GiB keystream); width 128 keeps it unreachable, so today's
  behavior is unchanged (r2's "pathological all-ones IV latent bug"
  claim was wrong — the relative counter means no IV value shortens the
  cycle — but slice 5 still moves the whole stream path off the
  panicking call as defense in depth).
- Passing `ctr_width` with any mode other than CTR raises `ValueError`
  via the existing misuse machine (voice-matched to the
  padding-with-stream-mode rejection); invalid widths raise `ValueError`
  naming the valid set. A non-int `ctr_width` raises `TypeError` instead
  (type errors are `TypeError`; catalog violations are `ValueError`) --
  `"ctr_width must be an int, got {type}"`. The ECB factories
  (`ecb_encryptor`/`ecb_decryptor`) do **not** grow an always-rejecting
  parameter; passing `ctr_width` there produces Python's natural
  `TypeError: unexpected keyword argument`, and that is the pinned,
  documented behavior.
- Little-endian counter variants are a **non-goal** until a real format
  demands one (RustCrypto ships `Ctr*LE`; adding a width/flavor is a
  table row, not a design change).

**Usage (the homegrown-format journey — PyCryptodome-style 64-bit split):**

```python
# Legacy Counter(nonce=nonce8, initial_value=n) layouts: rebuild the
# 16-byte initial counter block, then pick the matching width.
iv = nonce8 + initial_value.to_bytes(8, "big")
plaintext = key.decrypt(ciphertext, Mode.CTR, iv=iv, ctr_width=64)
```

### Contracts (normative)

- All RFC 0001 contracts stand unchanged for the existing surface (error
  catalog byte-stability, copy-while-GIL-held, GIL released around engine
  work, `DecryptionError` single channel, zeroization). Where this RFC
  creates **new** classes/paths, the equivalent contracts are restated
  above explicitly (GIL soundness, serialization posture, repr, and
  zeroization for `TwofishXTS`) — nothing is inherited by implication.
- **All length/range/argument validation happens in oxifish-owned code
  before any call into a dependency.** No dependency-internal `assert!`
  or panic (e.g. an XTS minimum-length assertion, `ctr`'s keystream
  exhaustion) is reachable from Python input. (Keystream exhaustion is
  surfaced through the dependency's *fallible* API and translated — see
  §3 — which satisfies this rule without duplicating the bound.)
- New error-catalog entries — exact strings normative now, house voice
  (templates render the actual values):
  - `"XTS key must be 32, 48, or 64 bytes (two 128, 192, or 256 bit halves), got {n} bytes"`
  - `"XTS key halves must not be equal"`
  - `"XTS data unit must be 16 to 16777216 bytes, got {n} bytes"`
  - `"tweak must be a non-negative integer less than 2**128, got {tweak}"`
  - `"invalid ctr_width {value}: expected one of 32, 64, 128"`
  - `"ctr_width is not supported for mode '{mode}': only mode 'ctr' accepts the ctr_width argument"`
  - `"CTR keystream exhausted: ctr_width={width} supports at most 2**{width} - 1 blocks per stream"`
- XTS `encrypt`/`decrypt` length-preservation (`len(out) == len(in)`) is a
  pinned property.
- `Mode` and `Padding` gain **no** members; the RFC 0002 sync machinery
  must pass untouched — that it would fail loudly if XTS were misfiled as
  a `Mode` is a design feature this RFC relies on.

### What it hides

Tweak-block encoding and Galois multiplication (XTS internals), ciphertext
stealing, the RustCrypto flavor-type zoo (`Ctr32BE`/`Ctr64BE`/`Ctr128BE`
monomorphizations), and the two-half key-schedule lifecycle.

## Non-goals

- **Pre-XTS TrueCrypt volumes** (LRW mode, 4.1–4.3a; whole-volume CBC
  before that) — structurally different tweakable/chaining modes with a
  vanishing corpus; would need their own construct. Named here so the
  Problem statement's disk-encryption claim is scoped honestly.
- **dm-crypt XTS-ESSIV** (hash-derived tweak) — `plain64` is served by
  the int tweak; ESSIV's derived tweak is the volume tool's business.
- **abi3 / limited-API wheels** — separate RFC (interacts with the release
  pipeline, not with this API surface).
- **Little-endian CTR flavors** — until a named format needs one.
- **Cipher cascades** (VeraCrypt AES-Twofish-Serpent) — the caller
  composes; each layer is an independent cipher call.
- **AEAD constructions** — no real-world Twofish pairing exists.
- **Volume/container format parsing** (VeraCrypt headers, KDBX, LUKS) —
  we are the cipher, not the format. (The test suite parses just enough
  VeraCrypt header to drive the golden-volume fixture; that is test
  scaffolding, not API.)
- **Other algorithms** — oxifish stays Twofish-only.
- **Upstream performance work** (table-based key schedule in the RustCrypto
  crate) — tracked as a separate upstream contribution, not RFC-gated.
- **Upstream XTS contribution** — RustCrypto has no XTS crate (their
  block-mode traits don't fit CTS's whole-data-unit shape). Our
  `src/xts.rs` is generic over any `cipher 0.5` block cipher and, once
  proven by this RFC's suite, is a plausible seed for contributing one;
  tracked like the perf work above, not RFC-gated. If an official crate
  ever ships, `TwofishXTS` swaps to it with zero API change.
- **pykeepass adoption PR** — follow-up outside this repo.

## Dependency Strategy

- **Slice 1 is a coordinated RustCrypto cipher-generation migration, not
  a one-crate bump.** `twofish 0.8.0` targets `cipher 0.5` (edition 2024,
  MSRV 1.85); Rust trait coherence makes cipher-0.4 and cipher-0.5 traits
  incompatible, so the whole graph moves together: **twofish 0.8.0,
  cipher 0.5.2, cbc 0.2.1, ctr 0.10.1, cfb-mode 0.9.1, ofb 0.7.1** (all
  published as a coordinated stable train 2026-04-10/2026-05-20; verified
  on crates.io). Consequences slice 1 owns:
  - Core trait renames, confirmed 1:1: `BlockEncrypt`→`BlockCipherEncrypt`,
    `BlockDecrypt`→`BlockCipherDecrypt`, `BlockEncryptMut`/`BlockDecryptMut`
    →`BlockModeEncrypt`/`BlockModeDecrypt`; `InnerIvInit` keeps its name.
  - **Not just renames:** `cipher 0.5` replaced `generic-array` with
    `hybrid-array` for `Block<C>` — every `Block::<Twofish>` construction
    site in `engine.rs` (~15: `from_slice`, `default`, `clone_from_slice`,
    `copy_from_slice`, the CFB partial-block helper, the cargo-test
    reference implementations) must be audited against `hybrid_array::
    Array`'s actual method set, which is close to but not identical to
    `GenericArray`'s.
  - **Cargo features:** `StreamCipherCoreWrapper` (the type behind the
    `Ctr*`/`Ofb` aliases) is now gated behind `cipher`'s non-default
    `stream-wrapper` feature — the `cipher` dependency needs
    `features = ["zeroize", "stream-wrapper"]`.
  - **Zeroize wiring is a hop change, not a removal** (r2 claimed `ctr
    0.10` dropped its `zeroize` feature; verified false): all five mode/
    cipher crates still expose `zeroize` features that now forward
    through `cipher 0.5`'s own `zeroize` feature. Keep
    `features = ["zeroize"]` on every crate plus `cipher`; the
    compile-time `assert_impl_all!(Twofish: ZeroizeOnDrop)` guard must
    stay green.
  - Docker toolchain check: rustc ≥ 1.85 / edition-2024 support (pyo3
    0.29's MSRV 1.83 floor is compatible; tumbleweed's rolling rustc
    almost certainly already exceeds 1.85 — check, don't assume).
  - RFC 0001's "Engine mechanism (pinned to real crate APIs)" prose is
    re-verified against the new majors; corrections there are a follow-up
    note, not silent drift.
  - Escalation triggers: the graph not compiling cleanly, or any KAT /
    exact-string pin shifting. The pins are the no-behavior-change proof.
- **XTS: in-repo implementation over the `cipher 0.5` traits is the
  primary path** (~100 lines: tweak encode, GF(2¹²⁸) doubling, CTS),
  generic over any 16-byte-block `BlockCipherEncrypt + BlockCipherDecrypt`
  implementor so the cargo tests can instantiate it with AES (`aes 0.9.1`,
  cipher-0.5-compatible, verified). The `xts-mode` crate fails this
  project's maintenance bar honestly — single maintainer, one release in
  3.5 years (0.5.1 2022-10 → 0.6.0 2026-05), explicitly unaudited — and
  holds its ciphers without any zeroize story of its own. In-repo keeps
  validation (no reachable asserts), zeroization, and error mapping under
  this repo's contracts. **`xts-mode 0.6.0` is used as a cargo
  *dev-dependency* oracle**: an independent implementation to
  cross-validate against (see Testing) — exactly the role an
  unaudited-but-plausible crate is fit for. Its CTS support was verified
  against its *source* (not docs summaries — a summarized read got this
  wrong once already): `encrypt_sector`/`decrypt_sector` handle
  non-multiple tails with the next-to-last/last tweak swap. (Version
  coupling, for the record: xts-mode 0.6 requires cipher 0.5, i.e. slice
  1; the 0.7-compatible fallback pairing would be xts-mode 0.5.1.)
- **CTR widths**: inside the existing `ctr` dependency. Note `ctr 0.10`
  reshaped its API around a `CtrFlavor` trait, but the `Ctr32BE`/
  `Ctr64BE`/`Ctr128BE` aliases survive; engine work is two new
  `Transform` variants (both `Kind::Stream`), a parameterized
  constructor, **and making `Session::ingest`'s Stream branch fallible**
  (today it calls the panicking `apply_keystream` and unconditionally
  returns `Ok` — the exhaustion contract requires `try_apply_keystream`
  plus an `EngineError` variant threaded through that shared path for
  all three widths and OFB alike).
- **XTS lives in a sibling module (`src/xts.rs`), not in
  `engine::Session`.** Everything in `Session` — the pending buffer,
  holdback, padding state machine, `Fresh→Streaming→Finalized` lifecycle —
  exists for streaming chaining modes; XTS is one-shot, per-data-unit,
  padding-free, two-scheduled. Threading it through `Transform`/`Kind`
  would add unreachable arms to every match. `engine.rs`/`session.rs`
  are untouched by slices 3–4.

## Testing Strategy

- **XTS layer correctness — IEEE 1619 XTS-AES vectors, including CTS.**
  There is no official Twofish-XTS vector set (verified: VeraCrypt's
  `Tests.c` self-tests XTS with **AES only**; its Twofish self-test is
  one raw ECB vector). Instead, the in-repo XTS engine is generic over
  the block cipher, and cargo tests instantiate it with AES to pass the
  IEEE 1619 (P1619/D16) Annex B vector set — **explicitly including
  Vectors 15–19, the "data unit that is not a multiple of 16 bytes"
  vectors (17/18/19/20-byte and multi-block-plus-tail plaintexts)**,
  which pin the ciphertext-stealing branch, tweak-order swap included,
  against an authoritative external source. Cite the vector numbers in
  the test names: half the annex is block-aligned and easy to mistake
  for the whole set. Vector 1 (Key1 == Key2) runs at this engine level
  (see §2's equal-halves scoping). GF-doubling correctness (LSB-first
  polynomial) is proven transitively by the multi-block vectors, not
  tested in isolation.
- **Twofish-XTS interop — VeraCrypt golden-volume fixture.** A minimal
  Twofish-only VeraCrypt container committed under `tests/fixtures/`
  (mirroring RFC 0001's KDBX golden-file precedent). Recipe pinned in
  the fixture README, scripted where possible: created with a pinned
  VeraCrypt version via the CLI (`veracrypt --text --non-interactive
  --create --encryption=Twofish --filesystem=none ...`), fixed password
  and PIM, known plaintext pattern written through the mapped device;
  target ≤ 1 MiB committed (VeraCrypt's floor is a few hundred KiB of
  header/metadata). **Master-key path (VeraCrypt has no key-export):**
  the test derives the header key itself (`hashlib.pbkdf2_hmac` with the
  pinned hash/iterations), Twofish-XTS-decrypts the 512-byte header with
  *oxifish* (tweak 0), and asserts VeraCrypt's own ground truth — the
  "VERA" magic and header CRC32s — before extracting the master keydata
  and decrypting a known data sector. The magic/CRC assertions are the
  independent proof: a wrong XTS implementation cannot produce them.
  (Fallback if header-parse scope creeps: a one-line master-key debug
  print in a source-built VeraCrypt, recorded in the recipe.) Note the
  fixture's 512-byte units are block-aligned — CTS coverage comes from
  the IEEE vectors and cross-validation, not from this fixture.
- **Independent-implementation cross-validation.**
  - *In cargo tests:* our in-repo XTS vs the `xts-mode` crate
    (dev-dependency) over randomized keys/tweaks/lengths, including every
    CTS tail residue — run **bidirectionally** (encrypt with ours /
    decrypt with theirs, and the reverse), the strongest structural
    defense against a self-consistent tweak-order-swap bug.
  - *In pytest:* reference implementations of XTS and split-counter CTR
    written into the test suite in pure Python **over the blessed ECB
    idiom** (`ecb_encryptor(padding=Padding.NONE)`), which is itself
    pinned by the official Twofish ECB KATs. The layered argument: block
    primitive proven by official vectors; mode layers proven by the IEEE
    vectors plus two independent reimplementations (Rust-vs-crate,
    Rust-vs-Python).
  - *Dropped in r2, for the record:* pykeepass's vendored
    `MODE_XTS`/`MODE_CTR` is dead code in the pinned dev-dep (chaining
    classes referenced but never defined — `NameError`; only `MODE_CBC`
    works). The existing CBC cross-validation stands; nothing new can be
    built on that module.
- **Property tests** — XTS round-trip across data-unit lengths 16..~600
  covering every CTS tail residue (`len % 16 ∈ 0..15`); tweak edges
  (0 and 2¹²⁸−1 accepted; −1 and 2¹²⁸ rejected with the cataloged
  string); tests above 2⁶⁴−1 labeled as IEEE-generality (VeraCrypt/
  dm-crypt interop lives in the 64-bit subset).
- **CTR width: wrap-correctness and exhaustion are separate tests.**
  - *Wrap + divergence (near-boundary IVs):* IVs whose low N bits sit at
    2^N − k for small k prove, within a few blocks, that widths
    32/64/128 produce different keystreams where they should, that the
    low-N-bit counter wraps through zero (matching the PyCryptodome-
    convention reference implementation), and that the high bits never
    carry.
  - *Exhaustion (seek-based):* the `2**N − 1`-block session limit is
    unreachable via test-sized payloads; reach it with
    `cipher::StreamCipherSeek` fast-forwarding the relative counter near
    the cycle end, then assert the cataloged `ValueError` (one-shot and
    mid-session), never a panic.
- **Misuse machine** — exact-string pins for every new catalog entry;
  `ctr_width` rejected for CBC/CFB/OFB via `ValueError`; the ECB-factory
  `TypeError` behavior pinned as such.
- **New-class contracts** — `TwofishXTS`: unpicklable/non-copyable,
  `__repr__` positive+negative pins, zeroization static assert coverage,
  bytearray-mutation-during-encrypt GIL-soundness test.
- **RFC 0002 machinery untouched and passing** — enum sync, README fence
  harness (new fences bump `_EXPECTED_FENCE_COUNT` and follow the fence
  rules; the XTS fence binds its own key and is documented-exempt from
  the IV-reuse guard; note the guard's `guarded_*_raw` wrappers hard-code
  the current `_encrypt_raw`/`_encryptor_raw` arities and must be updated
  in the slice that adds `ctr_width`), stubtest for the new stub entries,
  module docstring (doctested) updated to introduce **both** `TwofishXTS`
  and `ctr_width` — the homegrown-CTR audience gets a `help(oxifish)`
  example too, not just a README footnote.
- **Benchmark rows** — XTS and CTR-width rows added to
  `scripts/benchmark.py` (no threshold gate; datapoints for the upstream
  perf conversation).

## Documentation & release collateral

- **SECURITY.md gains two items** (slice 4, each its own line):
  1. *First-party XTS disclosure* — the tweak encoding, GF(2¹²⁸)
     doubling, and ciphertext stealing are oxifish's own implementation,
     not RustCrypto's, validated by the IEEE 1619 vector set (generic
     instantiation), bidirectional cross-validation against `xts-mode`,
     a pure-Python reference, and a real VeraCrypt volume. The project's
     "we bind audited implementations, we don't write cipher code" pitch
     changes at this one seam; SECURITY.md is where that must be said
     plainly.
  2. *Known Limitations: XTS* — paralleling the ECB bullet: tweak reuse
     across rewrites is correct (unlike IVs); a wrong tweak or wrong
     data-unit size silently yields garbage; XTS is unauthenticated like
     everything else here.
- **README** gets a short "which construct do I need?" pointer right
  after the intro (KDBX / OpenPGP / dm-crypt-CBC-ESSIV → `TwofishKey`;
  VeraCrypt / TrueCrypt ≥ 5.0 / dm-crypt-xts-plain64 → `TwofishXTS`;
  dead `twofish` package → the migration section) — the audience is
  someone who knows only "I have Twofish data."
- **Version:** this RFC ships as **0.3.0** (additive public surface →
  minor bump, per the project's own RFC 0001 precedent), with
  SECURITY.md's Supported Versions table updated (0.3.x supported;
  0.2.x row per the existing EOL convention) and a Breaking Changes-free
  release body noting the new class and kwarg.

## Slices

Order: 1, 2, 3, 4, 5, 6. Deps: 1 before 3/4/5 (cipher 0.5 underpins the
new engine work and the xts-mode/aes dev-deps); 3 before 4; 2 is
independent and can land anytime. [D] = requires the Docker cargo/maturin
rebuild — 4 rebuilds total.

1. **[D] RustCrypto cipher-generation migration (0.4 → 0.5).** Bump
   twofish/cipher/cbc/ctr/cfb-mode/ofb together to the versions pinned in
   Dependency Strategy; `cipher` gains `stream-wrapper` alongside
   `zeroize`; port `engine.rs` (4 trait renames + the `Block`/
   hybrid-array call-site audit — ~15 sites, close-but-not-identical
   API); confirm zeroize forwarding (static assert stays green;
   SECURITY.md only if the mechanism actually moved); Docker toolchain
   ≥ 1.85 check; full gates + benchmark before/after datapoint. KAT and
   exact-string pins prove no observable change; escalate if the graph
   won't compile cleanly or any pin shifts. One slice — the renames,
   array migration, and features all touch the same shared
   imports/`Block` sites, so a split would re-edit the same lines twice;
   budget it as the largest Rust slice here and treat a non-clean first
   Docker compile as expected, not as a signal to split.
2. **Migration docs for the dead `twofish` package.** README section +
   executable fence (bump `_EXPECTED_FENCE_COUNT`) showing both the
   single-block KAT idiom and the session-reuse loop (§1); SECURITY.md
   sentence on the ECB bullet; docstring cross-reference. No Rust, no
   rebuild; independent of slice 1.
3. **[D] XTS engine (Rust, `src/xts.rs`).** In-repo XTS over the cipher
   0.5 traits, generic over the block cipher: struct owning the two
   schedules, one-shot `encrypt_data_unit`/`decrypt_data_unit(data,
   tweak: u128)`, tweak-block encoding (here, not slice 4), CTS, all
   validation oxifish-owned, owned-buffer zeroization. Cargo tests:
   IEEE 1619 Annex B vectors via `aes` dev-dep — block-aligned AND
   Vectors 15–19 (CTS) AND Vector 1 (equal keys, engine-level only);
   bidirectional xts-mode 0.6 cross-validation incl. every CTS residue;
   zeroization assert. `engine.rs`/`session.rs` untouched.
4. **[D] XTS Python surface.** `TwofishXTS` in the pinned `TwofishKey`
   two-layer pattern: buffer coercion, key split + halves-differ check
   (facade-level, per §2 scoping), facade tweak-range validation
   (`ValueError`, not `OverflowError`), error-catalog strings, stubs +
   stubtest + `__all__`, serialization/repr/GIL-soundness contracts +
   tests, **VeraCrypt golden-volume fixture** (scripted recipe, pinned
   version, header-decrypt master-key path per Testing Strategy) as the
   first test action, pytest reference-XTS cross-validation + hypothesis
   round-trips, README section + fence + "which construct?" pointer,
   SECURITY.md: zeroization note, first-party-XTS disclosure, XTS
   Known-Limitations bullet (three distinct items).
5. **[D] CTR width (engine + surface, one slice).** Engine: two
   `Transform` variants via `Ctr32BE`/`Ctr64BE`, parameterized
   constructor, **`Session::ingest` Stream branch made fallible**
   (`try_apply_keystream` + new `EngineError` variant, all widths and
   OFB) — cargo tests prove wrap-through-zero and divergence via
   near-boundary counters and exhaustion via `StreamCipherSeek`.
   Surface: `ctr_width` kwarg on all four methods (both overloads),
   validation + catalog entries, stub update, `test_readme.py`
   guard-arity fix, pytest reference-CTR cross-validation
   (PyCryptodome-convention wrap semantics), module-docstring `ctr_width`
   example, docs.
6. **Benchmark + docs sweep + release collateral.** New benchmark rows;
   README/docstring pass under the executable-docs gates (module
   docstring introduces `TwofishXTS` and `ctr_width`); version → 0.3.0 +
   SECURITY.md Supported Versions update; RFC status + handoff update.
