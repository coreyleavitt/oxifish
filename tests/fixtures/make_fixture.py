"""Generates `tests/fixtures/twofish_golden.kdbx`, the KDBX4/Twofish golden
vector fixture used by `tests/test_kdbx_golden.py` (RFC 0001, slice 9).

RFC 0001's Testing Strategy originally specced this fixture as an
out-of-band, manually-produced input: "a KDBX4 fixture (Twofish cipher,
known password) created once, manually, via the KeePassXC GUI ... since
`keepassxc-cli db-create` has no cipher-selection flag." That GUI-only
assumption was a *fallback*, not a design commitment -- this script
supersedes it after slice 9's investigation established that pykeepass
*can* produce a valid KDBX4/Twofish database programmatically, with one
undocumented workaround (see below). Regenerate the fixture by running
this script from the repo root:

    uv run --no-sync python tests/fixtures/make_fixture.py

**Why pykeepass doesn't expose Twofish selection directly.** `PyKeePass.
create_database()` always clones pykeepass's bundled `blank_database.kdbx`
template, which is hard-coded to AES256 -- there is no `cipher=` keyword
anywhere in the public API. This script instead creates a database
normally, then reaches into the parsed `construct` object graph
(`kp.kdbx.header.value.dynamic_header.cipher_id.data`) and overwrites the
cipher selector to `"twofish"` before saving.

**The RawCopy gotcha (why this doesn't "just work").** pykeepass's file
header is parsed with construct's `RawCopy`, which caches the *raw bytes*
it originally read (`kp.kdbx.header.data`) alongside the parsed structure
(`kp.kdbx.header.value`). On build, `RawCopy` prefers `data` over `value`
whenever both are present (this is documented construct behavior, not a
pykeepass bug) -- so mutating `.value.dynamic_header.cipher_id.data` alone
is silently discarded at save time, and the on-disk header still reads
"aes256" while the payload is actually encrypted with whatever cipher the
mutated `.value` caused `TwoFishPayload.get_cipher`/`AES256Payload.
get_cipher` to select internally (Twofish, since payload encoding reads
`.value`, not `.data`). The result: a file whose header claims AES256 but
whose payload is Twofish ciphertext -- silently undecryptable garbage on
reopen (confirmed via manual reproduction: `zlib.error: Error -3` on the
resulting decompress, i.e. successful-looking decrypt into noise). The
fix, per construct's own `RawCopy` docstring ("delete the 'data' key when
modifying the 'value' key to correctly rebuild the former"), is
`del kp.kdbx.header.data` before saving. This forces `RawCopy` to
re-serialize the header from the (now-mutated) `.value`, so the on-disk
cipher_id GUID and the actual payload cipher agree.

**Independence of the oracle.** pykeepass does *not* use pyca/cryptography
or pycryptodome for the Twofish block cipher itself -- it vendors a pure-
Python, from-scratch Twofish implementation at
`pykeepass/kdbx_parsing/pytwofish.py` (wrapped by a small hand-rolled CBC
chaining class in `pykeepass/kdbx_parsing/twofish.py`). Cryptodome
(`pycryptodomex`) is used only for `Util.Padding` (PKCS7) and
`Util.strxor` -- not for the cipher core. This is a genuinely independent
implementation from oxifish's RustCrypto `twofish` crate (different
language, different codebase, different lineage), which is exactly what
makes the cross-check in `test_kdbx_golden.py` meaningful.

**Verified one-shot call site.** `pykeepass.kdbx_parsing.common.
DecryptedPayload._decode` calls `cipher.decrypt(payload_data)` exactly
once on the *entire* concatenated payload -- not chunked -- confirming the
RFC's "first action" premise (pykeepass's KDBX4 Twofish call site is
one-shot whole-payload) before any oracle-comparison test was written.
"""

from pathlib import Path

from pykeepass import PyKeePass, create_database

FIXTURE_PATH = Path(__file__).parent / "twofish_golden.kdbx"

# Fixed, known credentials -- regenerating this fixture must reproduce a
# byte-identical-enough database (same plaintext content; ciphertext will
# differ run-to-run because KeePass re-randomizes the master seed, IV, and
# KDF salt on every save). Tests must never assume a specific ciphertext,
# only that decrypting the *shipped* fixture reproduces this plaintext.
MASTER_PASSWORD = "oxifish-kdbx-twofish-golden-fixture"  # noqa: S105

ENTRY_TITLE = "oxifish golden vector"
ENTRY_USERNAME = "oxifish"
ENTRY_PASSWORD = "Tw0f1sh-RustCrypto-Cr0ss-Check!"  # noqa: S105
ENTRY_URL = "https://example.invalid/oxifish"
ENTRY_NOTES = (
    "RFC 0001 slice 9 KDBX golden-vector fixture. "
    "Do not edit by hand -- regenerate via make_fixture.py."
)


def main() -> None:
    if FIXTURE_PATH.exists():
        FIXTURE_PATH.unlink()

    kp = create_database(str(FIXTURE_PATH), password=MASTER_PASSWORD)

    kp.add_entry(
        kp.root_group,
        title=ENTRY_TITLE,
        username=ENTRY_USERNAME,
        password=ENTRY_PASSWORD,
        url=ENTRY_URL,
        notes=ENTRY_NOTES,
    )

    # Switch the cipher from the template's default (AES256) to Twofish.
    # See the module docstring for why both lines below are required.
    kp.kdbx.header.value.dynamic_header.cipher_id.data = "twofish"
    del kp.kdbx.header.data

    kp.save()

    # Verify: reopen with a fresh PyKeePass instance (independent parse,
    # not the in-memory object we just wrote) and confirm the cipher and
    # entry content round-tripped.
    reopened = PyKeePass(str(FIXTURE_PATH), password=MASTER_PASSWORD)
    assert reopened.encryption_algorithm == "twofish", reopened.encryption_algorithm
    entry = reopened.find_entries(title=ENTRY_TITLE, first=True)
    assert entry is not None, "fixture entry not found on reopen"
    assert entry.username == ENTRY_USERNAME
    assert entry.password == ENTRY_PASSWORD
    assert entry.url == ENTRY_URL
    assert entry.notes == ENTRY_NOTES

    print(
        f"Wrote {FIXTURE_PATH} "
        f"(cipher={reopened.encryption_algorithm}, kdf={reopened.kdf_algorithm})"
    )


if __name__ == "__main__":
    main()
