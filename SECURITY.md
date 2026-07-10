# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x: (EOL)           |

0.2.0 is a breaking-change release (the old per-mode class API is
removed; see the [release notes](https://github.com/coreyleavitt/oxifish/releases)
for the migration table). 0.1.x receives no further updates, including
security fixes — upgrade to 0.2.x.

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
  caller. Use CBC, CTR, CFB, or OFB for actual encryption.

For details on Twofish's security properties, see the [RustCrypto twofish crate](https://github.com/RustCrypto/block-ciphers/tree/master/twofish).

## Build Security

Wheels are built via GitHub Actions and published to PyPI using OIDC trusted publishing (no stored API tokens).
