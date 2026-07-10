"""Tests for RFC 0001's new surface: key object + module boundary.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 7 ("New surface:
key + module boundary"). This slice adds `oxifish.TwofishKey` (a thin
Python subclass of the Rust `_oxifish.TwofishKey` `#[pyclass(subclass)]`)
with construction validation, `key_size`, and `__repr__`; and pins
`Mode`/`Padding` as `StrEnum`s and `EncryptResult`/`DecryptionError` as
plain types. Streaming sessions and ECB factories are NOT part of this
slice -- they raise `AttributeError` today and land in later slices
(10-13). One-shot `encrypt`/`decrypt` (CBC only, explicit IV only) landed
in slice 8 -- see tests/test_one_shot_cbc.py.
"""

import pytest
from oxifish import (
    Buffer,
    DecryptionError,
    EncryptResult,
    Mode,
    Padding,
    TwofishKey,
)


class TestTwofishKeyConstruction:
    """`TwofishKey.__init__`: 16/24/32-byte keys, `ValueError` otherwise."""

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_accepts_every_valid_key_length(self, key_len: int) -> None:
        key = TwofishKey(bytes(range(key_len)))
        assert key.key_size == key_len

    @pytest.mark.parametrize("key_len", [0, 1, 15, 17, 23, 25, 31, 33, 64])
    def test_rejects_every_invalid_key_length(self, key_len: int) -> None:
        with pytest.raises(ValueError, match="16, 24, or 32 bytes"):
            TwofishKey(bytes(key_len))

    def test_accepts_bytearray(self) -> None:
        """Buffer = bytes | bytearray | memoryview (RFC Input types)."""
        key = TwofishKey(bytearray(range(16)))
        assert key.key_size == 16

    def test_accepts_memoryview(self) -> None:
        key = TwofishKey(memoryview(bytes(range(32))))
        assert key.key_size == 32

    def test_key_size_matches_byte_length_not_bit_length(self) -> None:
        # `key_size` reports bytes (16/24/32), distinct from the bit count
        # shown in __repr__ -- see TestTwofishKeyRepr below.
        assert TwofishKey(bytes(24)).key_size == 24


class TestTwofishKeyRejectsWrongTypes:
    """Code-review finding 11: `str`/`int` inputs to the `Buffer`
    coercion sites must raise a domain `TypeError` naming the parameter
    and what was received, not a raw/confusing CPython error -- and, for
    `int`, must not silently succeed. `bytes(int)` is valid Python
    (`bytes(16)` == 16 zero bytes), so without this rejection
    `TwofishKey(16)` would silently construct an all-zero 16-byte key."""

    def test_rejects_str_key_with_domain_message(self) -> None:
        with pytest.raises(TypeError, match=r"key must be a bytes-like object.*got str"):
            TwofishKey("sixteen-byte-key")  # type: ignore[arg-type]

    def test_rejects_str_key_hints_at_encode(self) -> None:
        with pytest.raises(TypeError, match=r"\.encode\("):
            TwofishKey("sixteen-byte-key")  # type: ignore[arg-type]

    def test_rejects_int_key_with_domain_message(self) -> None:
        with pytest.raises(TypeError, match=r"key must be a bytes-like object.*got int"):
            TwofishKey(16)  # type: ignore[arg-type]


class TestTwofishKeyRepr:
    """`__repr__` shows only `key_size` -- never key material.

    RFC Contracts: `__repr__` is "tested positively (documented fields
    present)" -- not pinned to one exact literal. Loosened from an
    over-pinned `repr(key) == "<TwofishKey key_size=...>"` equality check
    to substring assertions, mirroring `TwofishSession`'s repr tests'
    style (tests/test_streaming.py::TestRepr,
    tests/test_ecb.py::TestRepr)."""

    @pytest.mark.parametrize(("key_len", "bits"), [(16, 128), (24, 192), (32, 256)])
    def test_repr_shows_key_size_in_bits(self, key_len: int, bits: int) -> None:
        key = TwofishKey(bytes(key_len))
        r = repr(key)
        assert "TwofishKey" in r
        assert f"key_size={bits}" in r

    def test_repr_never_shows_key_material(self) -> None:
        raw = bytes.fromhex("ab" * 32)
        key = TwofishKey(raw)
        assert raw.hex() not in repr(key)
        assert "ab" not in repr(key)


class TestModeEnum:
    """`Mode` is a `StrEnum` covering the shared (non-ECB) session modes."""

    def test_values(self) -> None:
        assert str(Mode.CBC) == "cbc"
        assert str(Mode.CTR) == "ctr"
        assert str(Mode.CFB) == "cfb"
        assert str(Mode.OFB) == "ofb"

    def test_excludes_ecb(self) -> None:
        # ECB is deliberately unreachable via Mode -- only via the
        # dedicated ecb_encryptor/ecb_decryptor factories (later slices).
        assert not hasattr(Mode, "ECB")
        assert "ecb" not in {member.value for member in Mode}

    def test_is_str_subclass(self) -> None:
        assert isinstance(Mode.CBC, str)


class TestPaddingEnum:
    """`Padding` is a `StrEnum` covering all five padding schemes."""

    def test_values(self) -> None:
        assert str(Padding.PKCS7) == "pkcs7"
        assert str(Padding.NONE) == "none"
        assert str(Padding.ISO7816) == "iso7816"
        assert str(Padding.ANSIX923) == "ansix923"
        assert str(Padding.ZEROS) == "zeros"

    def test_is_str_subclass(self) -> None:
        assert isinstance(Padding.PKCS7, str)


class TestEncryptResult:
    """`EncryptResult` is the `(iv, ciphertext)` NamedTuple auto-IV
    `encrypt()` will return starting in slice 13 (see
    tests/test_one_shot_cbc.py's module docstring re: the slice-8/13
    split)."""

    def test_fields(self) -> None:
        result = EncryptResult(iv=b"i" * 16, ciphertext=b"c" * 16)
        assert result.iv == b"i" * 16
        assert result.ciphertext == b"c" * 16

    def test_unpacks_as_a_two_tuple(self) -> None:
        result = EncryptResult(iv=b"i" * 16, ciphertext=b"c" * 32)
        iv, ciphertext = result
        assert iv == result.iv
        assert ciphertext == result.ciphertext


class TestDecryptionError:
    """`DecryptionError` is the padded-decrypt failure type -- wired to
    actually fire in RFC 0001 slice 15 ("Misuse machine + DecryptionError";
    see tests/test_misuse_and_concurrency.py for the firing behavior).
    Pinned here as an importable `ValueError` subclass, defined in Rust
    (`pyo3::create_exception!`) and re-exported from `oxifish` since slice
    15 -- opaque from this module's perspective, which only exercises the
    Python-visible contract."""

    def test_is_a_value_error_subclass(self) -> None:
        assert issubclass(DecryptionError, ValueError)

    def test_raisable_and_catchable_as_value_error(self) -> None:
        with pytest.raises(ValueError):
            raise DecryptionError("decryption failed: invalid or corrupted ciphertext")


class TestNewSurfaceExports:
    """The new surface is importable from the top-level `oxifish` package
    and listed in `__all__` (matches the old API's export discipline)."""

    def test_all_new_names_are_exported(self) -> None:
        import oxifish

        for name in ("TwofishKey", "Mode", "Padding", "EncryptResult", "DecryptionError", "Buffer"):
            assert hasattr(oxifish, name), f"{name} not importable from oxifish"
            assert name in oxifish.__all__, f"{name} missing from oxifish.__all__"

    def test_buffer_is_the_documented_union(self) -> None:
        assert Buffer == (bytes | bytearray | memoryview)


class TestOldAPIIsGone:
    """RFC 0001 slice 16 ("Port docs, delete old API"): the pre-RFC
    per-mode class API, module-level `pad`/`unpad`, and the
    `PaddingStyle`/`KeySize`/`BlockSize` enums are deleted, not merely
    deprecated. `import oxifish` must never expose them again -- this is
    this slice's own regression test (RFC Testing Strategy: "TDD flavor:
    the deletion is verified by ... an import test that old names are
    truly gone")."""

    OLD_NAMES = (
        "TwofishECB",
        "TwofishCBC",
        "TwofishCTR",
        "TwofishCFB",
        "TwofishOFB",
        "TwofishCBCEncryptor",
        "TwofishCBCDecryptor",
        "TwofishCTRCipher",
        "TwofishCFBEncryptor",
        "TwofishCFBDecryptor",
        "TwofishOFBCipher",
        "PaddingStyle",
        "BlockSize",
        "KeySize",
        "pad",
        "unpad",
    )

    def test_old_names_are_not_attributes_of_the_package(self) -> None:
        import oxifish

        for name in self.OLD_NAMES:
            assert not hasattr(oxifish, name), f"{name} should have been deleted in slice 16"

    def test_old_names_are_not_in_all(self) -> None:
        import oxifish

        for name in self.OLD_NAMES:
            assert name not in oxifish.__all__

    @pytest.mark.parametrize("name", OLD_NAMES)
    def test_from_import_of_old_name_raises_import_error(self, name: str) -> None:
        # `from oxifish import <old name>` must raise ImportError, not
        # silently resolve to something else. `exec` is the only way to
        # exercise the actual `from X import Y` bytecode (IMPORT_FROM,
        # which does the attribute check) against a name computed at
        # test time -- there is no non-syntax equivalent.
        with pytest.raises(ImportError):
            exec(f"from oxifish import {name}")  # noqa: S102
