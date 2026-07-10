"""Tests for RFC 0001's KDBX golden vectors.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 9 ("KDBX golden
vectors"). Cross-checks `TwofishKey.decrypt` (RFC 0001 slice 8's one-shot
CBC hot path) against pykeepass's independent decryption of a real KDBX4
database encrypted with the Twofish cipher.

**Independence of the oracle (verified this slice, recorded here so the
claim is checkable without re-deriving it):** pykeepass does not use
pyca/cryptography or pycryptodome for the Twofish block cipher itself. It
vendors a from-scratch pure-Python implementation at
`pykeepass/kdbx_parsing/pytwofish.py` (a small hand-rolled CBC chaining
wrapper lives in `pykeepass/kdbx_parsing/twofish.py`); pycryptodomex is
used only for `Util.Padding` (PKCS7) and `Util.strxor`, never for the
cipher core. This is a genuinely independent implementation from
oxifish's RustCrypto `twofish` crate.

**Call-site shape (the RFC's "first action"):** `pykeepass.kdbx_parsing.
common.DecryptedPayload._decode` calls `cipher.decrypt(payload_data)`
exactly once on the entire concatenated payload -- one-shot, not chunked
-- so `TwofishKey.decrypt` (also one-shot) is the correct surface to
cross-check against, with no streaming-vs-one-shot mismatch to reconcile.

**Fixture provenance:** `tests/fixtures/twofish_golden.kdbx` is generated
by `tests/fixtures/make_fixture.py` (see that module's docstring for the
full recipe, including a documented pykeepass/construct gotcha). See
`tests/fixtures/README.md` for the regeneration command and fixed
credentials. Skipped cleanly (not failed) if the fixture is absent.
"""

import zlib
from pathlib import Path
from typing import Any

import pytest
from oxifish import Padding, TwofishKey
from pykeepass import PyKeePass
from pykeepass.kdbx_parsing import common

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "twofish_golden.kdbx"
FIXTURE_PASSWORD = "oxifish-kdbx-twofish-golden-fixture"  # noqa: S105

ENTRY_TITLE = "oxifish golden vector"
ENTRY_USERNAME = "oxifish"
ENTRY_URL = "https://example.invalid/oxifish"
ENTRY_NOTES = (
    "RFC 0001 slice 9 KDBX golden-vector fixture. "
    "Do not edit by hand -- regenerate via make_fixture.py."
)

pytestmark = pytest.mark.skipif(
    not FIXTURE_PATH.exists(),
    reason=(
        "tests/fixtures/twofish_golden.kdbx is missing -- see "
        "tests/fixtures/README.md to regenerate it "
        "(uv run --no-sync python tests/fixtures/make_fixture.py)."
    ),
)


def _capture_twofish_payload(path: Path, password: str) -> tuple[PyKeePass, bytes, bytes]:
    """Open `path` via pykeepass, capturing the exact ciphertext bytes fed
    to its Twofish CBC decrypt and the plaintext it decrypts them into.

    pykeepass exposes no public API for the raw encrypted payload -- it is
    consumed and discarded inside `DecryptedPayload._decode` while
    parsing. Monkeypatching `TwoFishPayload._decode` is the only seam;
    `master_key` and `encryption_iv` need no interception, since they
    survive on the parsed object as `kp.kdbx.body.master_key` and
    `kp.kdbx.header.value.dynamic_header.encryption_iv.data`.
    """
    captured: dict[str, bytes] = {}
    original = common.TwoFishPayload._decode

    def spy(self: Any, payload_data: bytes, con: Any, path_: Any) -> bytes:
        captured["ciphertext"] = payload_data
        result: bytes = original(self, payload_data, con, path_)
        captured["plaintext"] = result
        return result

    common.TwoFishPayload._decode = spy
    try:
        kp = PyKeePass(str(path), password=password)
    finally:
        common.TwoFishPayload._decode = original

    return kp, captured["ciphertext"], captured["plaintext"]


class TestKdbxGoldenVector:
    """Byte-exact cross-check: `TwofishKey.decrypt` against pykeepass's
    independent Twofish CBC decryption of the same fixture."""

    def test_decrypts_to_pykeepass_byte_exact_plaintext(self) -> None:
        kp, ciphertext, pykeepass_plaintext = _capture_twofish_payload(
            FIXTURE_PATH, FIXTURE_PASSWORD
        )
        assert kp.encryption_algorithm == "twofish"

        master_key = kp.kdbx.body.master_key
        iv = kp.kdbx.header.value.dynamic_header.encryption_iv.data

        oxifish_plaintext = TwofishKey(master_key).decrypt(ciphertext, iv=iv, padding=Padding.PKCS7)

        assert oxifish_plaintext == pykeepass_plaintext

    def test_decrypted_payload_contains_known_entry_fields(self) -> None:
        """Defense in depth: decompress the oxifish-decrypted payload
        (independently of pykeepass's own decompress/XML-parse path) and
        confirm the known, unprotected entry fields are present in the
        KDBX4 inner XML -- ruling out a decrypt that happens to byte-match
        pykeepass's plaintext through some shared-bug coincidence."""
        kp, ciphertext, _ = _capture_twofish_payload(FIXTURE_PATH, FIXTURE_PASSWORD)
        master_key = kp.kdbx.body.master_key
        iv = kp.kdbx.header.value.dynamic_header.encryption_iv.data

        oxifish_plaintext = TwofishKey(master_key).decrypt(ciphertext, iv=iv, padding=Padding.PKCS7)
        xml = zlib.decompress(oxifish_plaintext, 16 + 15)

        for expected in (ENTRY_TITLE, ENTRY_USERNAME, ENTRY_URL, ENTRY_NOTES):
            assert expected.encode() in xml

    def test_wrong_master_key_does_not_reproduce_plaintext(self) -> None:
        """Misuse control: decrypting with a wrong master key must not
        coincidentally reproduce the real plaintext (guards against a
        vacuously-true cross-check, e.g. a fixture with an all-zero key
        or a broken `master_key` extraction)."""
        kp, ciphertext, pykeepass_plaintext = _capture_twofish_payload(
            FIXTURE_PATH, FIXTURE_PASSWORD
        )
        iv = kp.kdbx.header.value.dynamic_header.encryption_iv.data
        wrong_key = bytes(b ^ 0xFF for b in kp.kdbx.body.master_key)

        try:
            wrong_plaintext = TwofishKey(wrong_key).decrypt(
                ciphertext, iv=iv, padding=Padding.PKCS7
            )
        except ValueError:
            return  # invalid padding byte -- also an acceptable outcome
        assert wrong_plaintext != pykeepass_plaintext
