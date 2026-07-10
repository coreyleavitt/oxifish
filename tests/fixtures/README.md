# tests/fixtures/

## `twofish_golden.kdbx`

A KDBX4 database encrypted with the Twofish cipher, used by
`tests/test_kdbx_golden.py` (RFC 0001, slice 9) as an independent-oracle
golden vector. pykeepass is the oracle: it decrypts the same file with its
own, from-scratch pure-Python Twofish implementation
(`pykeepass/kdbx_parsing/pytwofish.py` -- not pyca/cryptography, not
pycryptodome), and the test asserts oxifish's `TwofishKey.decrypt`
reproduces pykeepass's plaintext byte-for-byte.

**Fixed, known credentials** (regenerating the fixture must reproduce
these; only the ciphertext bytes differ between regenerations, because
KeePass re-randomizes the master seed, encryption IV, and KDF salt on
every save):

| | |
|---|---|
| Master password | `oxifish-kdbx-twofish-golden-fixture` |
| KDBX version | 4.0 |
| Cipher | Twofish (256-bit master key) |
| KDF | Argon2d (pykeepass's `create_database` default) |
| Entry title | `oxifish golden vector` |
| Entry username | `oxifish` |
| Entry password | `Tw0f1sh-RustCrypto-Cr0ss-Check!` |
| Entry URL | `https://example.invalid/oxifish` |
| Entry notes | `RFC 0001 slice 9 KDBX golden-vector fixture. Do not edit by hand -- regenerate via make_fixture.py.` |

### Regenerating (primary path): `make_fixture.py`

```sh
uv run --no-sync python tests/fixtures/make_fixture.py
```

This is the primary, supported recipe. RFC 0001's Testing Strategy
originally specced this fixture as an out-of-band, GUI-only input,
because `keepassxc-cli db-create` has no cipher-selection flag
(upstream keepassxreboot/keepassxc#13282). Slice 9's investigation found
that pykeepass *can* produce a valid KDBX4/Twofish database
programmatically, with one workaround: pykeepass's `create_database()`
always clones its bundled AES256 template, so the script overwrites
`kp.kdbx.header.value.dynamic_header.cipher_id.data` to `"twofish"`
after creation. That alone is silently discarded at save time because
pykeepass's file header is parsed with construct's `RawCopy`, which
prefers its cached raw bytes over the mutated parsed value unless you
also `del kp.kdbx.header.data` (construct's own `RawCopy` docstring
documents this exact "modify value, forget to clear data" pitfall). See
`make_fixture.py`'s module docstring for the full writeup, including how
this was diagnosed (a header that claims AES256 while the payload is
actually Twofish ciphertext -- decrypts into structured-looking garbage
that fails at `zlib.decompress`, not at the cipher layer, which is what
made it non-obvious).

The script also verifies its own output (reopens the file with a fresh
`PyKeePass` instance and checks the cipher + entry fields round-tripped)
before exiting, so a successful run is already a smoke test.

### Regenerating (fallback path): KeePassXC GUI

If pykeepass's Twofish support regresses or the programmatic path stops
working, fall back to the RFC's original manual recipe:

1. Install KeePassXC (any recent 2.7.x release; record the exact version
   used in the commit message when you regenerate the fixture this way).
2. **Database → New Database.**
   - Name: anything (not asserted by the tests).
   - Encryption Settings → **Encryption Algorithm: Twofish**.
   - Key Derivation Function: Argon2d (or whatever the current KeePassXC
     default is -- the tests only exercise the Twofish cipher, not a
     specific KDF; note the actual choice here if it's not Argon2d).
   - Master password: `oxifish-kdbx-twofish-golden-fixture` (exactly --
     the test file hardcodes this).
3. Add one entry with the title/username/password/URL/notes from the
   table above (exactly -- `test_kdbx_golden.py` asserts these strings
   appear in the decrypted, decompressed payload).
4. Save as `tests/fixtures/twofish_golden.kdbx`.
5. Update this README's version/KDF notes if they changed from the
   Argon2d/4.0 defaults above.

### Why a fixture at all, and why skip-not-fail without it

`tests/test_kdbx_golden.py` is guarded by
`pytest.mark.skipif(not FIXTURE_PATH.exists(), ...)` so the suite stays
green in any environment where the fixture hasn't been (re)generated
yet. If you see those tests skipped, run the regeneration command above.
