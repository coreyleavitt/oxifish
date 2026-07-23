# oxifish

Python bindings for the [RustCrypto Twofish](https://github.com/RustCrypto/block-ciphers) block cipher implementation.

A session-oriented API: construct a `TwofishKey` once, then either call
its one-shot `encrypt`/`decrypt` (the dominant case) or open a streaming
`TwofishSession` for incremental processing. Padding, IV handling, and
chunk buffering are handled internally — there is no separate `pad()`/
`unpad()` step and no manual block-alignment bookkeeping.

**Which construct do I need?** If you have Twofish-encrypted data from
KeePass/KDBX, OpenPGP, or a dm-crypt `twofish-cbc-essiv:sha256` volume —
`TwofishKey` (below). If you have a VeraCrypt volume, a TrueCrypt volume
(5.0 or later), or a dm-crypt/LUKS `twofish-xts-plain64` volume —
[`TwofishXTS`](#xts-disk-volume-encryption). If you're migrating off the
dead PyPI `twofish` package — see
["Migrating from the `twofish` package"](#migrating-from-the-twofish-package).

## Installation

```bash
pip install oxifish
```

## Usage

### One-shot (the hot path)

The KeePass use case — the IV lives in the KDBX header, so decrypting is
one line:

```python
from oxifish import TwofishKey

derived_key = bytes(range(32))  # stand-in for a KeePass-derived key
key = TwofishKey(derived_key)  # 16, 24, or 32 bytes

# In real usage, `ciphertext` and `header_iv` come from the KDBX file --
# synthesized here via a real encrypt() call so this block runs standalone.
header_iv, ciphertext = key.encrypt(b"a secret message")
plaintext = key.decrypt(ciphertext, iv=header_iv)  # PKCS7 padding by default
```

Encrypting without an IV of your own auto-generates one (via the OS
CSPRNG) and returns it alongside the ciphertext — the two values that
must travel together:

```python
iv, ciphertext = key.encrypt(plaintext)

# Store IV with ciphertext (IV is not secret)
encrypted_message = iv + ciphertext
```

Supplying your own IV returns bare ciphertext bytes instead (symmetric
with `decrypt`). In practice "your own IV" comes from an existing source
(e.g. a KDBX header) rather than being hand-generated — omitting `iv` and
letting `encrypt` generate one already does that safely; this fence draws
a fresh one only so it runs standalone:

```python
import secrets

from oxifish import Padding

aligned_data = bytes(range(32))  # Padding.NONE requires exact block multiples
iv2 = secrets.token_bytes(16)  # a fresh IV -- never reuse `iv` from above
ct = key.encrypt(aligned_data, iv=iv2, padding=Padding.NONE)
```

### Modes

`CBC` (the default), `CTR`, `CFB`, and `OFB` are selected via the `mode`
parameter on `encrypt`/`decrypt`/`encryptor`/`decryptor`:

```python
from oxifish import Mode

iv, ciphertext = key.encrypt(plaintext, Mode.CTR)
```

For `CTR`, `iv` is the full 16-byte initial counter block (big-endian
128-bit increment), not a nonce+counter split — unless you pass
`ctr_width`, which selects a narrower, NIST-style nonce||counter split:
only the low `ctr_width` bits of `iv` increment, matching legacy formats
built on PyCryptodome-style `Counter(nonce=..., initial_value=...)`
layouts (the dead `twofish` package's own users' homegrown CTR):

```python
nonce8 = bytes(range(8))
iv3 = nonce8 + (0).to_bytes(8, "big")  # 8-byte nonce || 8-byte BE counter
ciphertext64 = key.encrypt(aligned_data, Mode.CTR, iv=iv3, ctr_width=64)
key.decrypt(ciphertext64, Mode.CTR, iv=iv3, ctr_width=64)
```

`ctr_width` defaults to 128 (today's behavior: the whole IV is the
counter) and must be 32, 64, or 128; passing it for any mode other than
`CTR` raises `ValueError`. The low `ctr_width` bits wrap through zero as
they increment — that's expected, matching every real split-counter
format — but a single stream (one-shot, or summed across a session's
`update()` calls) is limited to `2**ctr_width - 1` blocks; asking for more
raises `ValueError` rather than silently reusing keystream. At
`ctr_width=128` that limit is unreachable by any real payload, so default
behavior is unchanged.

**Never reuse an `iv` under the same key.** For `CTR` and `OFB` this is
catastrophic: the keystream repeats, and XORing the two ciphertexts
recovers the XOR of the two plaintexts. `CFB` carries the same risk up to
the first differing block, after which the feedback register diverges.
For `CBC`, IV reuse leaks whether two messages share a common prefix.
Omitting `iv` and letting `encrypt`/`encryptor` auto-generate one via the
OS CSPRNG (see above) already does the right thing — only supply your own
IV when correctness requires it (e.g. KDBX interop, where the IV must
match the header), and never hand the same one to two encryptions under
one key.

### Padding

`padding` defaults to PKCS7 for CBC. Stream modes (CTR/CFB/OFB) never
take padding — passing any explicit value (including `Padding.NONE`)
raises `ValueError`, since there is nothing to pad.

```python
from oxifish import Padding

data = bytes(range(32))  # block-aligned so the Padding.NONE call below is valid too
key.encrypt(data, padding=Padding.PKCS7)   # default for CBC; iv omitted -> fresh each call
key.encrypt(data, padding=Padding.NONE)    # data must already be block-aligned
key.encrypt(data, padding=Padding.ISO7816)
key.encrypt(data, padding=Padding.ANSIX923)
key.encrypt(data, padding=Padding.ZEROS)   # ambiguous if plaintext ends in 0x00
```

### Streaming

For processing data incrementally, open a session bound to one mode, one
IV, and one padding policy:

```python
chunk1, chunk2 = b"first chunk of ", b"the message"

enc = key.encryptor(Mode.CFB)  # iv omitted -> fresh IV auto-generated, readable via enc.iv
ciphertext = enc.update(chunk1) + enc.update(chunk2) + enc.finalize()

dec = key.decryptor(Mode.CFB, iv=enc.iv)
plaintext = dec.update(ciphertext) + dec.finalize()
```

`update()` accepts chunks of any size — internal buffering handles
alignment. Padded-decrypt sessions withhold the most recent complete
block until `finalize()`, since it may carry padding. A session is
single-use: calling `update()`/`finalize()` after `finalize()` raises
`RuntimeError`.

### ECB

ECB does not provide semantic security and is reachable only through its
own factories — never through `mode=`:

```python
from oxifish import Padding

block = bytes(range(16))  # ECB processes exactly one block here
ciphertext = key.ecb_encryptor(padding=Padding.NONE).finalize(block)
plaintext = key.ecb_decryptor(padding=Padding.NONE).finalize(ciphertext)
```

`finalize(data)` accepting an argument is what keeps this a single
expression, since ECB has no dedicated one-shot method.

**Warning**: ECB mode leaks equal-block plaintext patterns at any
length — nothing enforces a single-block limit, so a caller can push an
arbitrarily large payload through `ecb_encryptor`/`ecb_decryptor` and get
full pattern leakage across it. The dedicated factories gate
*discoverability* (ECB is unreachable via the shared `mode=` parameter),
not payload size; keeping ECB use to single blocks is on the caller.
Restrict actual use to single blocks (e.g. known-answer tests) or
explicit interop.

### XTS (disk-volume encryption)

`TwofishXTS` is a structurally separate construct from everything above —
not reachable via `Mode` — for VeraCrypt, TrueCrypt (5.0 or later), and
dm-crypt/LUKS `twofish-xts-plain64` volumes. It takes one concatenated
double-length key instead of a single key, a per-call `tweak` (the
data-unit/sector number) instead of an IV, and no padding parameter —
ciphertext stealing handles data units that aren't a multiple of 16 bytes,
so `len(ciphertext) == len(data)` always. It is one-shot only: XTS is
random-access by construction (every data unit is encrypted/decrypted
independently), so there is no streaming session.

```python
from oxifish import TwofishXTS

# One concatenated key: the first half drives the data cipher, the second
# half drives the tweak (IEEE 1619's Key1 || Key2 order) -- e.g. VeraCrypt's
# volume-header "master keydata" field is exactly this shape. The two
# halves must differ; each half is independently 16, 24, or 32 bytes.
xts_key = bytes(range(32)) + bytes(range(32, 64))
xts = TwofishXTS(xts_key)

sector = bytes(512)  # VeraCrypt's data unit is always 512 bytes,
                      # regardless of the drive's physical sector size
byte_offset = 512 * 42
data_unit = byte_offset // 512  # NOT the OS's reported sector number

ciphertext = xts.encrypt(sector, tweak=data_unit)
plaintext = xts.decrypt(ciphertext, tweak=data_unit)
```

**The `tweak` is a position, not a nonce.** Unlike every IV-taking mode
above, reusing the same `tweak` to re-encrypt the same data unit is
*correct* — that's what a tweakable mode is for. The misuse case is the
*wrong* tweak for a position (silent garbage plaintext, no error), not a
repeated one. Do not carry the "never reuse an IV" rule from the rest of
this README over to `tweak=`; the fence above has no IV and is
intentionally exempt from that rule.

### Migrating from the `twofish` package

The PyPI [`twofish`](https://pypi.org/project/twofish/) package is
archived upstream and broken on Python 3.12+. Its entire API was
single-block `encrypt`/`decrypt` — callers built their own modes on top
of it. The migration target is the same bare block primitive shown
above: `ecb_encryptor`/`ecb_decryptor` with `Padding.NONE`. Composing
modes yourself on top of a raw block primitive is almost always a
mistake (that's why this library hides one behind `Mode`/`encrypt`
instead); this construct exists for known-answer tests and mechanical
migration, not for new designs.

```python
from oxifish import Padding

# One block (the KAT / known-answer shape -- what `twofish.encrypt()` did):
block_in = bytes(range(16))  # exactly one block
block_out = key.ecb_encryptor(padding=Padding.NONE).finalize(block_in)

# Many blocks (the real migration shape): ONE session, reused.
# ECB no-padding sessions flush eagerly -- update() returns each block
# immediately -- so a fresh session per block works but wastes a
# construction + FFI crossing per call.
migration_blocks = [bytes([i]) * 16 for i in range(4)]
enc_session = key.ecb_encryptor(padding=Padding.NONE)
migrated_ciphertext = (
    b"".join(enc_session.update(b) for b in migration_blocks) + enc_session.finalize()
)

# Decrypt direction: the same one-session-reused shape.
dec_session = key.ecb_decryptor(padding=Padding.NONE)
migrated_plaintext = (
    b"".join(
        dec_session.update(migrated_ciphertext[i : i + 16])
        for i in range(0, len(migrated_ciphertext), 16)
    )
    + dec_session.finalize()
)
```

## Errors

- `ValueError` — invalid key/IV length, an unrecognized `mode`/`padding`
  string (including `"ecb"`, which is reachable only via the `ecb_*`
  factories), a misaligned data length when `padding=Padding.NONE`, an
  explicit `padding` on a stream mode, an invalid `ctr_width` (must be 32,
  64, or 128) or `ctr_width` on a non-`CTR` mode, or CTR keystream
  exhaustion (`2**ctr_width - 1` blocks per stream — unreachable at the
  default `ctr_width=128`). For `TwofishXTS`: a key length outside
  {32, 48, 64} bytes, equal key halves, a data unit outside 16 bytes to
  16 MiB, or a `tweak` outside `0 <= tweak < 2**128`.
- `DecryptionError` (a `ValueError` subclass) — invalid or corrupted
  padded ciphertext. One fixed message closes the error-string side
  channel; this is **not** a constant-time guarantee (Twofish's
  key-dependent S-boxes are inherently non-constant-time). Wrong key,
  wrong IV, or wrong mode on unpadded data is not detected — it silently
  yields garbage plaintext, which is inherent to unauthenticated ciphers.
  If an attacker can submit chosen ciphertexts and observe whether
  `DecryptionError` is raised, that accept/reject channel is a padding
  oracle (a Vaudenay-style attack on CBC padding), regardless of the
  message-uniformity work above — the only real defense is
  encrypt-then-MAC with the MAC verified **before** any decryption is
  attempted, never decrypt-then-check.
- `RuntimeError` — raised by `update()`/`finalize()` on an
  already-finalized session; by concurrent access to the same session
  from two threads (PyO3's borrow-check error, distinct from the
  finalized-session message); and, rarely, if the OS CSPRNG fails during
  auto-generated IV creation.

## Security

This library is primarily intended for compatibility with existing
systems that require Twofish, such as KeePass databases. It implements
no authentication (AEAD) — callers needing integrity should use an outer
MAC, as KDBX does.

**Note**: Twofish is not constant-time due to key-dependent S-boxes. This
is fine for local file decryption but not suitable for server-side
encryption where timing attacks are feasible. For new projects, prefer
AES-GCM or ChaCha20-Poly1305.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and details on
key/IV zeroization.

## Development

Requires Rust and Python 3.11+.

```bash
# Install Rust if you haven't
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install uv if you haven't
curl -LsSf https://astral.sh/uv/install.sh | sh

# Build the extension and sync dev dependencies
uv sync --dev

# Run tests
uv run pytest
```

## License

MIT License. See [LICENSE](LICENSE) for details.

This project uses the [RustCrypto twofish crate](https://crates.io/crates/twofish) which is dual-licensed under MIT/Apache-2.0. We use it under the MIT license.
