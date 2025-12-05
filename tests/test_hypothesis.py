"""Property-based tests for oxifish using Hypothesis."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from oxifish import (
    Padding,
    TwofishCBC,
    TwofishCFB,
    TwofishCTR,
    TwofishECB,
    TwofishOFB,
)

# Strategies for generating test data
valid_key_lengths = st.sampled_from([16, 24, 32])
keys = valid_key_lengths.flatmap(lambda n: st.binary(min_size=n, max_size=n))
ivs = st.binary(min_size=16, max_size=16)
blocks = st.binary(min_size=16, max_size=16)
plaintexts = st.binary(min_size=0, max_size=1024)
non_empty_plaintexts = st.binary(min_size=1, max_size=1024)


class TestECBProperties:
    """Property-based tests for ECB mode."""

    @given(key=keys, block=blocks)
    def test_ecb_roundtrip(self, key: bytes, block: bytes) -> None:
        """encrypt_block(decrypt_block(x)) == x for any valid input."""
        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(block)
        decrypted = cipher.decrypt_block(ciphertext)
        assert decrypted == block

    @given(key=keys, block=blocks)
    def test_ecb_deterministic(self, key: bytes, block: bytes) -> None:
        """Same key and block always produce same ciphertext."""
        cipher1 = TwofishECB(key)
        cipher2 = TwofishECB(key)
        assert cipher1.encrypt_block(block) == cipher2.encrypt_block(block)

    @given(key=keys, block=blocks)
    def test_ecb_encrypt_does_not_crash(self, key: bytes, block: bytes) -> None:
        """Encryption should not crash for any valid input."""
        cipher = TwofishECB(key)
        cipher.encrypt_block(block)  # Just verify it doesn't crash


class TestCBCProperties:
    """Property-based tests for CBC mode."""

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cbc_pkcs7_roundtrip(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext with PKCS7 padding."""
        cipher1 = TwofishCBC(key, iv, Padding.Pkcs7)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(key, iv, Padding.Pkcs7)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cbc_iso7816_roundtrip(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext with ISO7816 padding."""
        cipher1 = TwofishCBC(key, iv, Padding.Iso7816)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(key, iv, Padding.Iso7816)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cbc_ansix923_roundtrip(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext with ANSI X9.23 padding."""
        cipher1 = TwofishCBC(key, iv, Padding.AnsiX923)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(key, iv, Padding.AnsiX923)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cbc_ciphertext_length(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """Ciphertext length should be next multiple of 16."""
        cipher = TwofishCBC(key, iv, Padding.Pkcs7)
        ciphertext = cipher.encrypt(plaintext)

        expected_len = ((len(plaintext) // 16) + 1) * 16
        assert len(ciphertext) == expected_len

    @given(key=keys, iv1=ivs, iv2=ivs, plaintext=non_empty_plaintexts)
    def test_cbc_different_ivs(
        self, key: bytes, iv1: bytes, iv2: bytes, plaintext: bytes
    ) -> None:
        """Different IVs should produce different ciphertext."""
        if iv1 == iv2:
            return  # Skip if IVs happen to be equal

        cipher1 = TwofishCBC(key, iv1)
        cipher2 = TwofishCBC(key, iv2)

        assert cipher1.encrypt(plaintext) != cipher2.encrypt(plaintext)


class TestCTRProperties:
    """Property-based tests for CTR mode."""

    @given(key=keys, nonce=ivs, plaintext=plaintexts)
    def test_ctr_roundtrip(self, key: bytes, nonce: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext."""
        cipher1 = TwofishCTR(key, nonce)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCTR(key, nonce)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, nonce=ivs, plaintext=plaintexts)
    def test_ctr_length_preserved(self, key: bytes, nonce: bytes, plaintext: bytes) -> None:
        """CTR mode should preserve plaintext length exactly."""
        cipher = TwofishCTR(key, nonce)
        ciphertext = cipher.encrypt(plaintext)
        assert len(ciphertext) == len(plaintext)

    @given(key=keys, nonce=ivs, plaintext=plaintexts)
    def test_ctr_encrypt_decrypt_same_operation(
        self, key: bytes, nonce: bytes, plaintext: bytes
    ) -> None:
        """In CTR mode, encrypt and decrypt are the same XOR operation."""
        cipher1 = TwofishCTR(key, nonce)
        cipher2 = TwofishCTR(key, nonce)

        # encrypt(x) should equal decrypt(x) for same key/nonce
        assert cipher1.encrypt(plaintext) == cipher2.decrypt(plaintext)


class TestCFBProperties:
    """Property-based tests for CFB mode."""

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cfb_roundtrip(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext."""
        cipher1 = TwofishCFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_cfb_length_preserved(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """CFB mode should preserve plaintext length exactly."""
        cipher = TwofishCFB(key, iv)
        ciphertext = cipher.encrypt(plaintext)
        assert len(ciphertext) == len(plaintext)


class TestOFBProperties:
    """Property-based tests for OFB mode."""

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_ofb_roundtrip(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """decrypt(encrypt(x)) == x for any plaintext."""
        cipher1 = TwofishOFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishOFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_ofb_length_preserved(self, key: bytes, iv: bytes, plaintext: bytes) -> None:
        """OFB mode should preserve plaintext length exactly."""
        cipher = TwofishOFB(key, iv)
        ciphertext = cipher.encrypt(plaintext)
        assert len(ciphertext) == len(plaintext)

    @given(key=keys, iv=ivs, plaintext=plaintexts)
    def test_ofb_encrypt_decrypt_same_operation(
        self, key: bytes, iv: bytes, plaintext: bytes
    ) -> None:
        """In OFB mode, encrypt and decrypt are the same XOR operation."""
        cipher1 = TwofishOFB(key, iv)
        cipher2 = TwofishOFB(key, iv)

        assert cipher1.encrypt(plaintext) == cipher2.decrypt(plaintext)


class TestInvalidInputs:
    """Property-based tests for invalid input handling."""

    @given(key=st.binary(min_size=0, max_size=64).filter(lambda k: len(k) not in (16, 24, 32)))
    def test_invalid_key_rejected(self, key: bytes) -> None:
        """Invalid key sizes should raise ValueError."""
        with pytest.raises(ValueError):
            TwofishECB(key)

    @given(iv=st.binary(min_size=0, max_size=64).filter(lambda iv: len(iv) != 16))
    def test_invalid_iv_rejected(self, iv: bytes) -> None:
        """Invalid IV sizes should raise ValueError."""
        key = b"\x00" * 16
        with pytest.raises(ValueError):
            TwofishCBC(key, iv)

    @given(block=st.binary(min_size=0, max_size=64).filter(lambda b: len(b) != 16))
    def test_invalid_block_rejected(self, block: bytes) -> None:
        """Invalid block sizes should raise ValueError for ECB."""
        cipher = TwofishECB(b"\x00" * 16)
        with pytest.raises(ValueError):
            cipher.encrypt_block(block)


class TestCrossMode:
    """Tests verifying modes behave differently."""

    @given(key=keys, iv=ivs, plaintext=non_empty_plaintexts)
    @settings(max_examples=50)
    def test_modes_produce_different_output(
        self, key: bytes, iv: bytes, plaintext: bytes
    ) -> None:
        """Different modes should produce different ciphertext."""
        cbc = TwofishCBC(key, iv, Padding.Pkcs7).encrypt(plaintext)
        ctr = TwofishCTR(key, iv).encrypt(plaintext)

        # CBC has padding so ciphertext is longer than stream modes
        assert len(cbc) != len(ctr)
