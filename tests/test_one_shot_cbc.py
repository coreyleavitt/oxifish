"""Tests for RFC 0001's one-shot CBC hot path.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 8 ("One-shot CBC
hot path (engine-routed; overload semantics)"). Adds `TwofishKey.encrypt`/
`decrypt` for CBC mode, routed through `_encrypt_raw`/`_decrypt_raw` onto a
fresh `engine::Session` per call -- the same `ingest`/`close_out` path
streaming sessions use (Contracts: engine unification).

**Scope decision (documented, not a silent guess):** the RFC's slice-8
bullet text reads "overload semantics (auto-IV -> EncryptResult; explicit
IV -> bytes)", but slice 13 is separately titled "Auto-IV (getrandom; .iv
contract)" and the Dependency Strategy section names `getrandom` as a
single, not-yet-landed boundary. This slice therefore implements the
explicit-IV overload only: `iv` is a required keyword argument on both
`encrypt` and `decrypt`, and `encrypt` always returns bare `bytes` (never
`EncryptResult`). The `iv=None` auto-generate overload lands in slice 13.
Likewise, `mode` is not yet a parameter -- CBC is implicit, matching the
"CBC hot path" title; `ctr`/`cfb`/`ofb` dispatch plus the mode/padding
misuse contracts are slice 10's deliverable.

`DecryptionError` wiring itself (RFC 0001 slice 15, "Misuse machine +
DecryptionError") is exercised in
tests/test_misuse_and_concurrency.py; this module keeps the coarser
`pytest.raises(ValueError, ...)` form for its padded-decrypt-failure tests
in `TestErrors` below since `DecryptionError` is a `ValueError` subclass
-- those assertions stayed accurate across slice 15 without edits, aside
from `TestErrors.test_decrypt_error_is_a_decryption_error`, which
specifically pinned the pre-slice-15 "not yet `DecryptionError`" gap and
is updated here to pin the post-slice-15 state instead of deleting the
coverage.
"""

import array

import pytest
from oxifish import DecryptionError, Padding, TwofishKey

KEY_16 = bytes(range(16))
KEY_24 = bytes(range(24))
KEY_32 = bytes(range(32))
IV = bytes(range(16, 32))

ALL_PADDINGS = [Padding.PKCS7, Padding.ISO7816, Padding.ANSIX923, Padding.ZEROS]


class TestRoundTrip:
    """encrypt/decrypt round-trips for every key size and padding."""

    @pytest.mark.parametrize("key", [KEY_16, KEY_24, KEY_32])
    def test_round_trips_for_every_key_size(self, key: bytes) -> None:
        key_obj = TwofishKey(key)
        plaintext = b"a message that is not block aligned!"
        ciphertext = key_obj.encrypt(plaintext, iv=IV)
        assert key_obj.decrypt(ciphertext, iv=IV) == plaintext

    @pytest.mark.parametrize("padding", ALL_PADDINGS)
    def test_round_trips_for_every_padding(self, padding: Padding) -> None:
        key_obj = TwofishKey(KEY_32)
        plaintext = b"twenty-byte-long msg"
        ciphertext = key_obj.encrypt(plaintext, iv=IV, padding=padding)
        assert key_obj.decrypt(ciphertext, iv=IV, padding=padding) == plaintext

    def test_round_trips_for_padding_none_with_aligned_data(self) -> None:
        key_obj = TwofishKey(KEY_32)
        plaintext = b"0123456789abcdef" * 3  # 48 bytes, block-aligned
        ciphertext = key_obj.encrypt(plaintext, iv=IV, padding=Padding.NONE)
        assert key_obj.decrypt(ciphertext, iv=IV, padding=Padding.NONE) == plaintext

    def test_padding_string_and_enum_member_are_interchangeable(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"hello"
        via_enum = key_obj.encrypt(plaintext, iv=IV, padding=Padding.ISO7816)
        via_string = key_obj.encrypt(plaintext, iv=IV, padding="iso7816")
        assert via_enum == via_string


class TestDefaultPadding:
    """`padding=None` means PKCS7 for CBC (RFC Contracts: Padding defaults)."""

    def test_omitted_padding_matches_explicit_pkcs7(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"default padding check"
        assert key_obj.encrypt(plaintext, iv=IV) == key_obj.encrypt(
            plaintext, iv=IV, padding=Padding.PKCS7
        )

    def test_omitted_padding_matches_explicit_pkcs7_string(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"default padding check"
        assert key_obj.encrypt(plaintext, iv=IV) == key_obj.encrypt(
            plaintext, iv=IV, padding="pkcs7"
        )

    def test_decrypt_omitted_padding_matches_explicit_pkcs7(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"round trip me", iv=IV, padding=Padding.PKCS7)
        assert key_obj.decrypt(ciphertext, iv=IV) == key_obj.decrypt(
            ciphertext, iv=IV, padding=Padding.PKCS7
        )


class TestEmptyMessageMatrix:
    """RFC Contracts: empty-message matrix, pinned by test."""

    @pytest.mark.parametrize("padding", [Padding.PKCS7, Padding.ANSIX923, Padding.ISO7816])
    def test_padded_schemes_encrypt_empty_to_one_full_block(self, padding: Padding) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"", iv=IV, padding=padding)
        assert len(ciphertext) == 16

    @pytest.mark.parametrize("padding", [Padding.ZEROS, Padding.NONE])
    def test_zeros_and_none_encrypt_empty_to_empty(self, padding: Padding) -> None:
        key_obj = TwofishKey(KEY_16)
        assert key_obj.encrypt(b"", iv=IV, padding=padding) == b""

    def test_pkcs7_empty_message_round_trips(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"", iv=IV, padding=Padding.PKCS7)
        assert key_obj.decrypt(ciphertext, iv=IV, padding=Padding.PKCS7) == b""

    def test_none_padding_empty_ciphertext_decrypts_to_empty(self) -> None:
        key_obj = TwofishKey(KEY_16)
        assert key_obj.decrypt(b"", iv=IV, padding=Padding.NONE) == b""


class TestZerosScopedToFinalBlock:
    """RFC Contracts: "zeros" unpad strips only the held-back final block,
    not the whole buffer -- a genuine zero run straddling the final block
    boundary must survive in earlier blocks."""

    def test_zero_run_straddling_final_block_boundary_is_preserved(self) -> None:
        key_obj = TwofishKey(KEY_32)
        # First block (16 bytes) is real plaintext genuinely ending in
        # eight 0x00 bytes -- not held back, never unpadded. The second,
        # incomplete block ("tail", 4 bytes) gets zero-padded to 16 bytes
        # by encrypt(); only *that* block's padding zeros are stripped by
        # decrypt(). The old, deleted `unpad()` scanned the whole buffer
        # and would have eaten the first block's real trailing zeros too
        # (RFC Contracts: "zeros" unpad is scoped to the held-back final
        # block only) -- this test would fail under that old behavior.
        first_block = b"real-dat" + b"\x00" * 8
        assert len(first_block) == 16
        plaintext = first_block + b"tail"
        assert len(plaintext) == 20

        ciphertext = key_obj.encrypt(plaintext, iv=IV, padding=Padding.ZEROS)
        decrypted = key_obj.decrypt(ciphertext, iv=IV, padding=Padding.ZEROS)
        assert decrypted == plaintext


class TestKnownAnswerCrossCheck:
    """`padding="none"` one-shot output matches the official Twofish CBC
    KATs."""

    def test_vector1_128bit(self) -> None:
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")

        ciphertext = TwofishKey(key).encrypt(plaintext, iv=iv, padding=Padding.NONE)
        assert ciphertext == expected

    def test_vector2_192bit(self) -> None:
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        iv = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("742ca6db422942b78c47ef6c7db185d8")

        ciphertext = TwofishKey(key).encrypt(plaintext, iv=iv, padding=Padding.NONE)
        assert ciphertext == expected

    def test_vector3_256bit(self) -> None:
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        iv = bytes.fromhex("fedcba9876543210fedcba9876543210")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("8cb4fcbf0d29b43cb760563d68dd0530")

        ciphertext = TwofishKey(key).encrypt(plaintext, iv=iv, padding=Padding.NONE)
        assert ciphertext == expected


class TestBufferInputTypes:
    """RFC Contracts: Input types -- `data` accepts bytes, bytearray,
    memoryview. `iv` accepts the same `Buffer` union, coerced like `data`
    (RFC Contracts: "iv parameters accept any Buffer ... coerced like
    data" -- widened from bytes-only in stage-4 review, finding 3; see the
    `bytearray`/`memoryview` `iv` tests below)."""

    def test_accepts_bytearray_data(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(bytearray(b"bytearray data!!"), iv=IV)
        assert key_obj.decrypt(ciphertext, iv=IV) == b"bytearray data!!"

    def test_accepts_memoryview_data(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(memoryview(b"memoryview data!"), iv=IV)
        assert key_obj.decrypt(ciphertext, iv=IV) == b"memoryview data!"

    def test_encrypt_accepts_bytearray_iv_and_matches_bytes_iv(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"iv as any buffer type"
        zero_iv = bytes(16)
        via_bytes_iv = key_obj.encrypt(plaintext, iv=zero_iv)
        via_bytearray_iv = key_obj.encrypt(plaintext, iv=bytearray(16))
        assert via_bytearray_iv == via_bytes_iv
        assert key_obj.decrypt(via_bytearray_iv, iv=zero_iv) == plaintext

    def test_decrypt_accepts_memoryview_iv_and_matches_bytes_iv(self) -> None:
        key_obj = TwofishKey(KEY_16)
        zero_iv = bytes(16)
        ciphertext = key_obj.encrypt(b"iv as any buffer type", iv=zero_iv)
        via_bytes_iv = key_obj.decrypt(ciphertext, iv=zero_iv)
        via_memoryview_iv = key_obj.decrypt(ciphertext, iv=memoryview(bytes(16)))
        assert via_memoryview_iv == via_bytes_iv

    def test_encrypt_still_accepts_array_array_data(self) -> None:
        # Code-review finding 11's fix must reject `str`/`int` without
        # narrowing acceptance to a `bytes`/`bytearray`/`memoryview`
        # isinstance whitelist -- any other buffer-protocol object (e.g.
        # `array.array`) must keep working.
        key_obj = TwofishKey(KEY_16)
        data = array.array("B", b"array data!!!!!!")
        ciphertext = key_obj.encrypt(data, iv=IV)  # type: ignore[call-overload]
        assert key_obj.decrypt(ciphertext, iv=IV) == bytes(data)


class TestWrongTypeCoercion:
    """Code-review finding 11: `str`/`int` inputs to `data`/`iv` must
    raise a domain `TypeError` naming the parameter and what was
    received -- never a raw/confusing CPython error, and never (for
    `int`, since `bytes(int)` is valid Python) silently succeed."""

    def test_encrypt_rejects_str_data_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got str"):
            key_obj.encrypt("not bytes", iv=IV)  # type: ignore[call-overload]

    def test_encrypt_rejects_int_data_with_domain_message(self) -> None:
        # `key.encrypt(5)` today silently encrypts five zero bytes
        # (`bytes(5) == b"\x00" * 5`) -- must become an error.
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got int"):
            key_obj.encrypt(5, iv=IV)  # type: ignore[call-overload]

    def test_decrypt_rejects_str_data_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got str"):
            key_obj.decrypt("not bytes", iv=IV)  # type: ignore[arg-type]

    def test_decrypt_rejects_int_data_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got int"):
            key_obj.decrypt(5, iv=IV)  # type: ignore[arg-type]

    def test_encrypt_rejects_str_iv_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got str"):
            key_obj.encrypt(b"data", iv="sixteen-byte-iv!")  # type: ignore[call-overload]

    def test_encrypt_rejects_int_iv_with_domain_message(self) -> None:
        # `key.decrypt(ct, iv=16)` today silently uses an all-zero IV
        # (`bytes(16) == 16 zero bytes`) -- must become an error, both
        # here (encrypt's explicit-iv overload) and on decrypt below.
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got int"):
            key_obj.encrypt(b"data", iv=16)  # type: ignore[call-overload]

    def test_decrypt_rejects_str_iv_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got str"):
            key_obj.decrypt(bytes(16), iv="sixteen-byte-iv!")  # type: ignore[arg-type]

    def test_decrypt_rejects_int_iv_with_domain_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got int"):
            key_obj.decrypt(bytes(16), iv=16)  # type: ignore[arg-type]


class TestErrors:
    """Catalogued error strings (RFC 0001's Error catalog + this slice's
    IV-length validation)."""

    @pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
    def test_encrypt_rejects_wrong_iv_length(self, bad_len: int) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key_obj.encrypt(b"data", iv=bytes(bad_len))

    @pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
    def test_decrypt_rejects_wrong_iv_length(self, bad_len: int) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key_obj.decrypt(bytes(16), iv=bytes(bad_len))

    def test_encrypt_rejects_unknown_padding_string(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid padding 'bogus': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'",
        ):
            key_obj.encrypt(b"data", iv=IV, padding="bogus")

    def test_decrypt_rejects_unknown_padding_string(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid padding 'bogus': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'",
        ):
            key_obj.decrypt(bytes(16), iv=IV, padding="bogus")

    @pytest.mark.parametrize("bad_padding", ["PKCS7", "pkcs7 "])
    def test_padding_string_matching_is_case_sensitive_and_exact(self, bad_padding: str) -> None:
        # Mirrors tests/test_one_shot_modes.py::TestUnknownModeRejection.
        # test_mode_string_matching_is_case_sensitive_and_exact (RFC
        # Contracts: "Mode/Padding strings match exactly" -- no trimming,
        # no normalization).
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=rf"invalid padding '{bad_padding}': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'",
        ):
            key_obj.encrypt(b"data", iv=IV, padding=bad_padding)

    @pytest.mark.parametrize("padding", ALL_PADDINGS)
    def test_decrypt_rejects_empty_ciphertext_under_every_padded_scheme(
        self, padding: Padding
    ) -> None:
        # RFC Contracts: DecryptionError fires when "total padded
        # ciphertext [is] shorter than one block (including zero bytes)".
        # `b""` is the boundary case -- distinct from `padding="none"`,
        # whose `b""` is the symmetric empty-message case, not an error.
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            DecryptionError, match=r"^decryption failed: invalid or corrupted ciphertext$"
        ):
            key_obj.decrypt(b"", iv=IV, padding=padding)

    def test_encrypt_padding_none_rejects_misaligned_data(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError, match=r"data length \(11\) is not a multiple of the block size \(16\)"
        ):
            key_obj.encrypt(b"not aligned", iv=IV, padding=Padding.NONE)

    def test_decrypt_padding_none_rejects_misaligned_data(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError, match=r"data length \(11\) is not a multiple of the block size \(16\)"
        ):
            key_obj.decrypt(b"not aligned", iv=IV, padding=Padding.NONE)

    def test_decrypt_rejects_corrupted_pkcs7_padding(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"valid message", iv=IV, padding=Padding.PKCS7)
        # Flip a byte in the last (padded) block to corrupt the padding.
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with pytest.raises(ValueError, match=r"decryption failed: invalid or corrupted ciphertext"):
            key_obj.decrypt(corrupted, iv=IV, padding=Padding.PKCS7)

    def test_decrypt_rejects_ciphertext_shorter_than_one_block(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"decryption failed: invalid or corrupted ciphertext"):
            key_obj.decrypt(b"short", iv=IV, padding=Padding.PKCS7)

    def test_decrypt_error_is_a_decryption_error(self) -> None:
        # RFC 0001 slice 15 ("Misuse machine + DecryptionError") wires
        # padded-decrypt failures to `DecryptionError` specifically, not
        # just any `ValueError` -- this pins the post-slice-15 state
        # (formerly the gap this test's name and docstring described).
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(DecryptionError) as exc_info:
            key_obj.decrypt(b"short", iv=IV, padding=Padding.PKCS7)
        assert isinstance(exc_info.value, ValueError)
