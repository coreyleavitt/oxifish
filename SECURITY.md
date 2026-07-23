# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x: (EOL)           |
| 0.1.x   | :x: (EOL)           |

0.3.0 is an additive release (new `TwofishXTS` disk-volume construct and
the `ctr_width` keyword; no breaking changes — see the [release
notes](https://github.com/coreyleavitt/oxifish/releases)). 0.2.0 was a
breaking-change release (the old per-mode class API is removed; see the
release notes for the migration table). 0.2.x and 0.1.x receive no
further updates, including security fixes — upgrade to 0.3.x.

## Reporting a Vulnerability

Please report security vulnerabilities by emailing the maintainers directly rather than opening a public issue. We will acknowledge receipt within 48 hours.

## Security Features

### Key and IV Zeroization

Key and IV material is cleared from memory on drop via the `zeroize`
crate (enabled on `twofish`, `cipher`, and every RustCrypto mode crate
this library uses), which prevents the compiler from optimizing the clear
away. Two lifetime models apply, depending on what's holding the
material:

- **`TwofishKey`** holds a reference-counted `Arc<Twofish>` schedule.
  ECB sessions (`ecb_encryptor`/`ecb_decryptor`) borrow that same `Arc`
  rather than cloning it. The schedule is zeroized once, on the *last*
  drop of the `Arc` — i.e. once the key and every ECB session derived
  from it have all been dropped.
- **Every non-ECB session** (CBC/CTR/CFB/OFB, from `encryptor`/
  `decryptor`, and the internal sessions backing one-shot `encrypt`/
  `decrypt`) owns an independent clone of the key schedule (184 bytes of
  expanded round keys — never a re-derivation from the raw key) and
  zeroizes that clone on *its own* drop, independently of the parent
  `TwofishKey` and of any other session.

Raw key bytes passed to `TwofishKey()` are copied into the expanded
schedule once, at construction, and never copied again afterward.

**What's zeroized beyond the key schedule**: the engine's own transient
plaintext copies are cleared too, not just key material. The sub-block
residue buffer (`Pending`, which holds not-yet-transformed input across
`update()` calls) and the CBC/ECB padded-decrypt holdback block
(`HeldBlock`, which holds one decrypted block awaiting padding
resolution) are both zeroized on overwrite and on drop.

**Caveat inherent to `zeroize` generally**: drop-based zeroization clears
the copies this library owns and knows about. It cannot retroactively
erase transient stack copies the compiler's optimizer may have
introduced during moves earlier in a value's lifetime (registers,
spills) — this is a property of how Rust (and `zeroize`) work, not
specific to this crate — nor can it reach copies that end up in
Python-managed memory (see below).

**Note**: Python's garbage collector controls when objects are dropped.
For sensitive applications, keep `TwofishKey`/`TwofishSession` scope
narrow and avoid storing keys in long-lived variables.

**Python-side key bytes**: `TwofishKey.__new__` coerces its `key`
argument through `bytes(key)` before construction, and the caller's own
key object (however it was built) is a normal Python object too — both
are immutable and outside this library's reach, so they persist in
Python-managed memory until garbage collected and the allocator reuses
that memory. This is standard for Python crypto bindings — the
`cryptography`/PyCA library has the same caveat — and matters mainly if
your threat model includes memory disclosure; scope key-bearing
variables narrowly if it does.

**`TwofishXTS`** (RFC 0003) zeroizes in full, not just its two key
schedules. Both expanded `Twofish` schedules (the data-key half and the
tweak-key half) are zeroized on drop, matching `TwofishKey`'s model above.
In addition — because XTS has no `engine::Session` to hide transient
buffers behind — the owned copy of each call's input buffer (made while
the GIL is held, see "Concurrency" below) and the engine's returned output
buffer are explicitly zeroized once they've been copied out to the Python
`bytes` object the caller receives; the ciphertext-stealing scratch used
internally for non-block-multiple data units is zeroized the same way,
inside the Rust XTS engine itself. The same Python-side-key-bytes caveat
above applies to `TwofishXTS`'s `key` argument, with one addition: the
facade's `_split_xts_key` splits the coerced key into `key1`/`key2`
halves, each a distinct, immutable `bytes` object outside this library's
reach and subject to the same limitation as the original `key` argument.

### First-party XTS implementation

Unlike the rest of this library — which binds RustCrypto's audited
`twofish`/`cbc`/`ctr`/`cfb-mode`/`ofb` crates and adds no cipher-mode code
of its own — **`TwofishXTS`'s XTS-mode logic is oxifish's own
implementation**, not RustCrypto's: RustCrypto has no XTS crate (its
block-mode traits don't fit ciphertext stealing's whole-data-unit shape).
The tweak-block encoding, GF(2¹²⁸) doubling, and ciphertext stealing
(`src/xts.rs`, ~100 lines) are hand-written against the `cipher` 0.5
traits. This is the one seam where this project's usual "we bind audited
implementations, we don't write cipher code" pitch does not hold, and it's
said plainly here rather than left implicit.

That implementation is validated four independent ways: the official IEEE
1619 (P1619/D16) Annex B known-answer vector set, generically instantiated
with AES in cargo tests (including the ciphertext-stealing vectors, not
just the block-aligned ones); bidirectional cross-validation against the
independent `xts-mode` crate (a cargo dev-dependency oracle, run both
encrypt-ours/decrypt-theirs and the reverse); an independent pure-Python
XTS reference implementation in the pytest suite, built over this
library's own KAT-pinned ECB primitive; and a real VeraCrypt volume
(`tests/fixtures/`, when present — see that directory's README for the
recipe and current status).

## Known Limitations

- **Not constant-time**: Twofish uses key-dependent S-boxes, which are
  inherently non-constant-time. This is suitable for local file
  decryption (KeePass databases) but not for server-side encryption where
  timing attacks are feasible. `DecryptionError` closes the
  error-*string* side channel (one fixed message for every padded-decrypt
  failure) but makes no constant-time claim beyond that — see the
  library's docstrings for the exact scope.
- **No authentication (AEAD)**: this library implements unauthenticated
  encryption only. Callers needing integrity must use an outer MAC (as
  KDBX does). Wrong key, wrong IV, or wrong mode on unpadded data is not
  detected and silently yields garbage plaintext. If an attacker can
  submit chosen ciphertexts to a decryption endpoint and observe whether
  `DecryptionError` is raised, that accept/reject signal is a padding
  oracle (a Vaudenay-style attack on CBC padding) — the message-uniformity
  work above reduces incidental leakage but is **not** a defense against
  an online oracle. The only real defense is encrypt-then-MAC with the
  MAC verified *before* any decryption is attempted; never decrypt first
  and check second.
- **IV/counter reuse is caller-catastrophic**: reusing an `iv` under the
  same key is not detected or prevented by this library. For CTR and OFB,
  reuse repeats the keystream, letting an attacker recover the XOR of two
  plaintexts from the XOR of the corresponding ciphertexts; CFB carries
  the same risk up to the first differing block. For CBC, IV reuse leaks
  whether two messages share a common prefix. Omit `iv` on `encrypt`/
  `encryptor` and let the CSPRNG-backed auto-generated IV do the right
  thing by default; never pass the same IV to two encryptions under one
  key.
- **ECB mode**: provided for compatibility and KAT/interop use only, via
  the dedicated `ecb_encryptor`/`ecb_decryptor` factories. It leaks
  equal-block plaintext patterns at any length — the factories restrict
  discoverability, not payload size, so multi-block ECB use is on the
  caller. This is also the documented migration path off the dead PyPI
  `twofish` package (see the README), which was itself a bare
  single-block primitive with the same pattern-leakage exposure for any
  caller who processes more than one block through it. Use CBC, CTR,
  CFB, or OFB for actual encryption.
- **XTS (`TwofishXTS`)**: tweak reuse across rewrites of the same data
  unit is *correct* here, unlike IV reuse everywhere else in this library
  — see the README's "tweak is a position, not a nonce" note. A wrong
  tweak, or a data-unit size that doesn't match the format being decoded
  (e.g. assuming a drive's physical 4Kn sector size instead of
  VeraCrypt's fixed 512-byte data unit), silently yields garbage
  plaintext with no error, the same failure mode as a wrong key or IV
  elsewhere in this library. Like every other construct here, XTS is
  unauthenticated — it provides no integrity guarantee, only
  confidentiality.

For details on Twofish's security properties, see the [RustCrypto twofish crate](https://github.com/RustCrypto/block-ciphers/tree/master/twofish).

## Build Security

Wheels are built via GitHub Actions and published to PyPI using OIDC trusted publishing (no stored API tokens).
