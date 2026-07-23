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

## `twofish_xts.vc` (RFC 0003 slice 4) -- BLOCKED, not yet committed

RFC 0003's Testing Strategy calls for a minimal Twofish-only VeraCrypt
golden volume here, mirroring `twofish_golden.kdbx` above: the test would
derive the header key itself (`hashlib.pbkdf2_hmac`, pinned PRF/
iterations), XTS-decrypt the 512-byte header with *oxifish*
(`TwofishXTS`, tweak 0), assert VeraCrypt's own "VERA" magic + header
CRC32s as independent ground truth, then extract the master keydata and
decrypt a known plaintext pattern written to a data sector through a live
VeraCrypt mount. This slice attempted that recipe first, per the brief;
it is documented here as a discrete, environment-specific blocker rather
than failing the whole slice, with a verified-working recipe for a
machine that doesn't hit the same wall.

### What was tried (this environment: WSL2, `6.6.87.2-microsoft-standard-WSL2`)

1. **VeraCrypt CLI install -- succeeded.** No VeraCrypt package exists in
   Debian's repos, so the official console-only build was fetched
   directly from the GitHub release
   (`veracrypt-console-1.26.29-Debian-12-amd64.deb`, from
   `github.com/veracrypt/VeraCrypt`'s `VeraCrypt_1.26.29` release) inside
   a `debian:12` Docker container and installed via `apt install
   ./veracrypt-console-*.deb`. `veracrypt --version` reported `1.26.29`.
2. **Volume creation -- succeeded.** `veracrypt --text --non-interactive
   --create` with `--size=1MiB --encryption=Twofish --hash=sha512
   --filesystem=none --pim=0 --password=<fixed>` (see the exact command
   below) produced a valid 1 MiB container with no errors, run inside a
   `--privileged` container.
3. **Mounting (`--filesystem=none`) -- failed, root cause identified.**
   VeraCrypt's Linux backend mounts a `--filesystem=none` volume via the
   kernel's `dm-crypt` (`device-mapper` "crypt" target), which requires
   the volume's cipher to be registered in the *kernel's* crypto API --
   this is independent of any Docker flag or privilege level, since a
   container shares its host's kernel and cannot add ciphers to it.
   - The failure (`Error: device-mapper: reload ioctl on veracrypt1
     (254:0) failed: No such file or directory`) was isolated to the
     kernel crypto layer by a control experiment: a hand-built
     `dmsetup create` table using `aes-xts-plain64` against a loop
     device (a cipher this kernel *does* have) succeeded cleanly in the
     same container/privilege configuration that failed for Twofish --
     ruling out `--privileged`, `/dev` visibility, `dm_crypt` module
     load state (confirmed loaded: `lsmod | grep dm_crypt`), and loop
     device support (confirmed working: `losetup` round-tripped) as the
     cause.
   - `grep -i twofish /proc/crypto` returns nothing on this host, and no
     `twofish*.ko` exists anywhere under `/lib/modules/$(uname -r)`
     (searched the full tree) -- this WSL2 kernel was simply not built
     with `CONFIG_CRYPTO_TWOFISH`. There is no non-root way to add a
     kernel module here, and no root/sudo credential was available to
     even test whether one could be loaded if present.
   - **This is a genuine kernel-capability gap, not a container/
     permission issue**: any process on this host, containerized or
     not, hits the same wall, because dm-crypt's cipher registry lives
     in the one shared kernel. Rebuilding or patching a Microsoft-
     supplied WSL2 kernel image is out of scope for this slice.

### Ready-to-run recipe (for a machine with kernel Twofish support)

Most mainline/distro desktop kernels ship `CONFIG_CRYPTO_TWOFISH` as a
module. Verify first: `sudo modprobe twofish; grep -i twofish
/proc/crypto` should list `twofish` (and, once dm-crypt loads it,
`xts(twofish)`). If that succeeds, the rest of this recipe is expected to
complete end-to-end (steps 1-2 are independently verified working, above;
only step 3 onward is unverified beyond that point):

```sh
# 1. Install VeraCrypt console (pin whatever version you use in this
#    README's own notes when you regenerate the fixture).
curl -LO https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.26.29/veracrypt-console-1.26.29-<your-distro>-amd64.deb
sudo apt install ./veracrypt-console-1.26.29-<your-distro>-amd64.deb

# 2. Create the volume (verified working recipe -- reproduces exactly
#    what this slice already produced in Docker). A few hundred KiB
#    larger than the strict 1 MiB target leaves clear room for a real
#    data area distinct from the header/backup-header region; check the
#    actual header size for your VeraCrypt version (Volume Format
#    Specification, below) and size accordingly, then shrink back toward
#    1 MiB if the layout allows it.
veracrypt --text --non-interactive --create tests/fixtures/twofish_xts.vc \
  --volume-type=normal --size=4MiB --encryption=Twofish --hash=sha512 \
  --filesystem=none --pim=0 --keyfiles= --random-source=/dev/urandom \
  --password=oxifish-xts-golden-fixture

# 3. Mount with --filesystem=none (no filesystem is created or expected;
#    the raw mapped block device is what gets written to directly).
sudo veracrypt --text --non-interactive --filesystem=none --pim=0 \
  --password=oxifish-xts-golden-fixture tests/fixtures/twofish_xts.vc
veracrypt --text -l   # note the mapped device, e.g. /dev/mapper/veracrypt1

# 4. Write a known plaintext pattern at a data-unit-aligned offset
#    that's safely inside the data area (past the header + backup
#    header -- confirm the exact boundary against the Volume Format
#    Specification rather than guessing; record the byte offset used
#    here, since the test needs it to compute the matching tweak =
#    byte_offset // 512).
sudo dd if=<(python3 -c "import sys; sys.stdout.buffer.write((bytes(range(256))*2)[:512])") \
  of=/dev/mapper/veracrypt1 bs=512 seek=<data_unit_index> count=1 conv=notrunc,fsync

# 5. Unmount.
sudo veracrypt --text -d tests/fixtures/twofish_xts.vc
```

**Master-key/header-parse path (test side, not yet written):** derive the
header key with `hashlib.pbkdf2_hmac("sha512", password.encode(), salt,
iterations, dklen)`, XTS-decrypt the first 512 bytes of the file with
`TwofishXTS` at `tweak=0`, and assert the decrypted header starts with
the ASCII magic `"VERA"` plus valid CRC32s over the documented header
fields, before extracting the master keydata (`key1 || key2`, the actual
volume's XTS key) and decrypting the data sector written in step 4 above
with `TwofishXTS`. **Do not guess the salt offset, PBKDF2 iteration
count, or header field offsets** -- verify each against the [VeraCrypt
Volume Format
Specification](https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html)
and the `github.com/veracrypt/VeraCrypt` source (`Volume.cpp`,
`Pkcs5Kdf.cpp`) for the exact VeraCrypt version used to create the
fixture -- both the iteration count and (for very new versions) the
default PRF have changed across VeraCrypt releases.

### Why skip-not-fail without it

Once this fixture and its accompanying `tests/test_xts_veracrypt_golden.py`
(not yet written) exist, that module should follow
`tests/test_kdbx_golden.py`'s convention: `pytest.mark.skipif(not
FIXTURE_PATH.exists(), ...)`, so the suite stays green in any environment
(such as this one) where the fixture can't be (re)generated.
