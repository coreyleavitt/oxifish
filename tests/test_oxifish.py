"""Tests for oxifish Twofish implementation."""

import pytest

from oxifish import BLOCK_SIZE, TwofishCBC, TwofishECB, block_size


class TestBlockSize:
    """Tests for block size constants."""

    def test_block_size_constant(self) -> None:
        """Test BLOCK_SIZE constant is 16."""
        assert BLOCK_SIZE == 16

    def test_block_size_function(self) -> None:
        """Test block_size() returns 16."""
        assert block_size() == 16


class TestTwofishECB:
    """Tests for TwofishECB class."""

    def test_valid_key_sizes(self) -> None:
        """Test that 16, 24, and 32 byte keys are accepted."""
        for key_len in (16, 24, 32):
            key = b"\x00" * key_len
            cipher = TwofishECB(key)
            assert cipher is not None

    def test_invalid_key_size(self) -> None:
        """Test that invalid key sizes raise ValueError."""
        for key_len in (0, 8, 15, 17, 31, 33, 64):
            with pytest.raises(ValueError, match="Key must be"):
                TwofishECB(b"\x00" * key_len)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test that encrypt/decrypt is reversible."""
        key = b"0123456789abcdef"
        plaintext = b"Hello, World!!!"  # Exactly 16 bytes
        assert len(plaintext) == 16

        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext
        assert ciphertext != plaintext

    def test_invalid_block_size(self) -> None:
        """Test that non-16-byte blocks raise ValueError."""
        cipher = TwofishECB(b"\x00" * 16)

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.encrypt_block(b"short")

        with pytest.raises(ValueError, match="Block must be 16 bytes"):
            cipher.decrypt_block(b"too long for a block!!")

    # Official Twofish test vectors from the specification
    # https://www.schneier.com/academic/twofish/
    def test_vector_128bit_key(self) -> None:
        """Test against official 128-bit key test vector."""
        key = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9F589F5CF6122C32B6BFEC2F2AE8C35A")

        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected

    def test_vector_192bit_key(self) -> None:
        """Test against official 192-bit key test vector."""
        key = bytes.fromhex("0123456789ABCDEFFEDCBA98765432100011223344556677")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("CFD1D2E5A9BE9CDF501F13B892BD2248")

        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected

    def test_vector_256bit_key(self) -> None:
        """Test against official 256-bit key test vector."""
        key = bytes.fromhex(
            "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF"
        )
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("37527BE0052334B89F0CFCCAE87CFA20")

        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(plaintext)

        assert ciphertext == expected


class TestTwofishCBC:
    """Tests for TwofishCBC class."""

    def test_valid_key_and_iv(self) -> None:
        """Test that valid key and IV are accepted."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        cipher = TwofishCBC(key, iv)
        assert cipher is not None

    def test_invalid_iv_size(self) -> None:
        """Test that invalid IV sizes raise ValueError."""
        key = b"\x00" * 16

        with pytest.raises(ValueError, match="IV must be 16 bytes"):
            TwofishCBC(key, b"\x00" * 8)

        with pytest.raises(ValueError, match="IV must be 16 bytes"):
            TwofishCBC(key, b"\x00" * 32)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CBC encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher1 = TwofishCBC(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        # Ciphertext should be padded to 16 bytes
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_decrypt_multi_block(self) -> None:
        """Test CBC with multiple blocks."""
        key = b"\x00" * 32
        iv = b"\x00" * 16
        plaintext = b"A" * 100  # Will pad to 112 bytes (7 blocks)

        cipher1 = TwofishCBC(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        assert len(ciphertext) == 112

        cipher2 = TwofishCBC(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Test encrypting empty plaintext."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        cipher1 = TwofishCBC(key, iv)
        ciphertext = cipher1.encrypt(b"")

        # Empty plaintext gets full block of padding
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == b""

    def test_invalid_ciphertext_length(self) -> None:
        """Test that non-block-aligned ciphertext raises ValueError."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        cipher = TwofishCBC(key, iv)

        with pytest.raises(ValueError, match="must be non-empty and multiple of 16"):
            cipher.decrypt(b"not aligned")

        with pytest.raises(ValueError, match="must be non-empty and multiple of 16"):
            cipher.decrypt(b"")

    def test_different_ivs_produce_different_ciphertext(self) -> None:
        """Test that different IVs produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher1 = TwofishCBC(key, b"\x00" * 16)
        ciphertext1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(key, b"\xff" * 16)
        ciphertext2 = cipher2.encrypt(plaintext)

        assert ciphertext1 != ciphertext2

    def test_different_keys_produce_different_ciphertext(self) -> None:
        """Test that different keys produce different ciphertext."""
        iv = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher1 = TwofishCBC(b"\x00" * 16, iv)
        ciphertext1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(b"\xff" * 16, iv)
        ciphertext2 = cipher2.encrypt(plaintext)

        assert ciphertext1 != ciphertext2


class TestPKCS7Padding:
    """Tests for PKCS7 padding behavior."""

    def test_padding_lengths(self) -> None:
        """Test that padding produces correct lengths."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        # Test various input lengths
        test_cases = [
            (0, 16),  # Empty -> 16 bytes padding
            (1, 16),  # 1 byte -> 15 bytes padding
            (15, 16),  # 15 bytes -> 1 byte padding
            (16, 32),  # 16 bytes -> 16 bytes padding (full block)
            (17, 32),  # 17 bytes -> 15 bytes padding
            (31, 32),  # 31 bytes -> 1 byte padding
            (32, 48),  # 32 bytes -> 16 bytes padding (full block)
        ]

        for input_len, expected_output_len in test_cases:
            cipher = TwofishCBC(key, iv)
            ciphertext = cipher.encrypt(b"x" * input_len)
            assert len(ciphertext) == expected_output_len, (
                f"Input {input_len} bytes should produce {expected_output_len} bytes, "
                f"got {len(ciphertext)}"
            )
