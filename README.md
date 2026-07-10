# oxifish

Python bindings for the [RustCrypto Twofish](https://github.com/RustCrypto/block-ciphers) block cipher implementation.

A session-oriented API: construct a `TwofishKey` once, then either call
its one-shot `encrypt`/`decrypt` (the dominant case) or open a streaming
`TwofishSession` for incremental processing. Padding, IV handling, and
chunk buffering are handled internally — there is no separate `pad()`/
`unpad()` step and no manual block-alignment bookkeeping.

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

key = TwofishKey(derived_key)  # 16, 24, or 32 bytes
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
with `decrypt`):

```python
from oxifish import Padding

ct = key.encrypt(aligned_data, iv=iv, padding=Padding.NONE)
```

### Modes

`CBC` (the default), `CTR`, `CFB`, and `OFB` are selected via the `mode`
parameter on `encrypt`/`decrypt`/`encryptor`/`decryptor`:

```python
from oxifish import Mode

iv, ciphertext = key.encrypt(plaintext, Mode.CTR)
```

For `CTR`, `iv` is the full 16-byte initial counter block (big-endian
128-bit increment), not a nonce+counter split.

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

key.encrypt(data, iv=iv, padding=Padding.PKCS7)   # default for CBC
key.encrypt(data, iv=iv, padding=Padding.NONE)    # data must already be block-aligned
key.encrypt(data, iv=iv, padding=Padding.ISO7816)
key.encrypt(data, iv=iv, padding=Padding.ANSIX923)
key.encrypt(data, iv=iv, padding=Padding.ZEROS)   # ambiguous if plaintext ends in 0x00
```

### Streaming

For processing data incrementally, open a session bound to one mode, one
IV, and one padding policy:

```python
enc = key.encryptor(Mode.CFB, iv=iv)
ciphertext = enc.update(chunk1) + enc.update(chunk2) + enc.finalize()

dec = key.decryptor(Mode.CFB, iv=iv)
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

## Errors

- `ValueError` — invalid key/IV length, an unrecognized `mode`/`padding`
  string (including `"ecb"`, which is reachable only via the `ecb_*`
  factories), a misaligned data length when `padding=Padding.NONE`, or an
  explicit `padding` on a stream mode.
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
