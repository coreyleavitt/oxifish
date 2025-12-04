"""Tests for oxifish Twofish implementation."""

import pytest
from oxifish import (
    BLOCK_SIZE,
    Padding,
    TwofishCBC,
    TwofishCFB,
    TwofishCTR,
    TwofishECB,
    TwofishOFB,
    block_size,
)


class TestBlockSize:
    """Tests for block size constants."""

    def test_block_size_constant(self) -> None:
        """Test BLOCK_SIZE constant is 16."""
        assert BLOCK_SIZE == 16

    def test_block_size_function(self) -> None:
        """Test block_size() returns 16."""
        assert block_size() == 16


class TestPadding:
    """Tests for Padding enum."""

    def test_padding_values(self) -> None:
        """Test that all padding values are accessible."""
        assert Padding.Pkcs7 is not None
        assert Padding.NoPadding is not None
        assert Padding.Zeros is not None
        assert Padding.Iso7816 is not None
        assert Padding.AnsiX923 is not None


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
        plaintext = b"Hello, World!!!!"  # Exactly 16 bytes
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
        key = bytes.fromhex("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
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

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            TwofishCBC(key, b"\x00" * 8)

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            TwofishCBC(key, b"\x00" * 32)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CBC encrypt/decrypt roundtrip with default PKCS7 padding."""
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


class TestCBCPaddingOptions:
    """Tests for CBC mode with different padding options."""

    def test_pkcs7_padding_roundtrip(self) -> None:
        """Test PKCS7 padding roundtrip."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Hello!"

        cipher1 = TwofishCBC(key, iv, Padding.Pkcs7)
        ciphertext = cipher1.encrypt(plaintext)
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv, Padding.Pkcs7)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_no_padding_block_aligned(self) -> None:
        """Test no padding with block-aligned data."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Exactly16bytes!!"
        assert len(plaintext) == 16

        cipher1 = TwofishCBC(key, iv, Padding.NoPadding)
        ciphertext = cipher1.encrypt(plaintext)
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv, Padding.NoPadding)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_no_padding_unaligned_raises(self) -> None:
        """Test that no padding with unaligned data raises ValueError."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Not aligned"

        cipher = TwofishCBC(key, iv, Padding.NoPadding)
        with pytest.raises(ValueError, match="must be a multiple of 16 bytes"):
            cipher.encrypt(plaintext)

    def test_zero_padding_roundtrip(self) -> None:
        """Test zero padding roundtrip."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        # Use plaintext that doesn't end with zeros
        plaintext = b"Hello!"

        cipher1 = TwofishCBC(key, iv, Padding.Zeros)
        ciphertext = cipher1.encrypt(plaintext)
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv, Padding.Zeros)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_iso7816_padding_roundtrip(self) -> None:
        """Test ISO 7816-4 padding roundtrip."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Hello!"

        cipher1 = TwofishCBC(key, iv, Padding.Iso7816)
        ciphertext = cipher1.encrypt(plaintext)
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv, Padding.Iso7816)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_ansix923_padding_roundtrip(self) -> None:
        """Test ANSI X9.23 padding roundtrip."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Hello!"

        cipher1 = TwofishCBC(key, iv, Padding.AnsiX923)
        ciphertext = cipher1.encrypt(plaintext)
        assert len(ciphertext) == 16

        cipher2 = TwofishCBC(key, iv, Padding.AnsiX923)
        decrypted = cipher2.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_pkcs7_padding_lengths(self) -> None:
        """Test that PKCS7 padding produces correct lengths."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

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
            cipher = TwofishCBC(key, iv, Padding.Pkcs7)
            ciphertext = cipher.encrypt(b"x" * input_len)
            assert len(ciphertext) == expected_output_len, (
                f"Input {input_len} bytes should produce {expected_output_len} bytes, "
                f"got {len(ciphertext)}"
            )


class TestTwofishCTR:
    """Tests for TwofishCTR class."""

    def test_valid_key_and_nonce(self) -> None:
        """Test that valid key and nonce are accepted."""
        key = b"\x00" * 16
        nonce = b"\x00" * 16
        cipher = TwofishCTR(key, nonce)
        assert cipher is not None

    def test_invalid_nonce_size(self) -> None:
        """Test that invalid nonce sizes raise ValueError."""
        key = b"\x00" * 16

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            TwofishCTR(key, b"\x00" * 8)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CTR encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        nonce = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher1 = TwofishCTR(key, nonce)
        ciphertext = cipher1.encrypt(plaintext)

        # CTR mode: output same length as input
        assert len(ciphertext) == len(plaintext)

        cipher2 = TwofishCTR(key, nonce)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_no_padding_needed(self) -> None:
        """Test that CTR mode doesn't require padding."""
        key = b"\x00" * 16
        nonce = b"\x00" * 16

        # Test various lengths that aren't block-aligned
        for length in [1, 7, 15, 17, 100]:
            plaintext = b"x" * length

            cipher1 = TwofishCTR(key, nonce)
            ciphertext = cipher1.encrypt(plaintext)
            assert len(ciphertext) == length

            cipher2 = TwofishCTR(key, nonce)
            decrypted = cipher2.decrypt(ciphertext)
            assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Test encrypting empty plaintext."""
        key = b"\x00" * 16
        nonce = b"\x00" * 16

        cipher = TwofishCTR(key, nonce)
        ciphertext = cipher.encrypt(b"")

        assert ciphertext == b""

    def test_different_nonces_produce_different_ciphertext(self) -> None:
        """Test that different nonces produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher1 = TwofishCTR(key, b"\x00" * 16)
        ciphertext1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishCTR(key, b"\xff" * 16)
        ciphertext2 = cipher2.encrypt(plaintext)

        assert ciphertext1 != ciphertext2


class TestTwofishCFB:
    """Tests for TwofishCFB class."""

    def test_valid_key_and_iv(self) -> None:
        """Test that valid key and IV are accepted."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        cipher = TwofishCFB(key, iv)
        assert cipher is not None

    def test_invalid_iv_size(self) -> None:
        """Test that invalid IV sizes raise ValueError."""
        key = b"\x00" * 16

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            TwofishCFB(key, b"\x00" * 8)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CFB encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher1 = TwofishCFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        # CFB mode: output same length as input
        assert len(ciphertext) == len(plaintext)

        cipher2 = TwofishCFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_no_padding_needed(self) -> None:
        """Test that CFB mode doesn't require padding."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        for length in [1, 7, 15, 17, 100]:
            plaintext = b"x" * length

            cipher1 = TwofishCFB(key, iv)
            ciphertext = cipher1.encrypt(plaintext)
            assert len(ciphertext) == length

            cipher2 = TwofishCFB(key, iv)
            decrypted = cipher2.decrypt(ciphertext)
            assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Test encrypting empty plaintext."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        cipher = TwofishCFB(key, iv)
        ciphertext = cipher.encrypt(b"")

        assert ciphertext == b""

    def test_different_ivs_produce_different_ciphertext(self) -> None:
        """Test that different IVs produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher1 = TwofishCFB(key, b"\x00" * 16)
        ciphertext1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishCFB(key, b"\xff" * 16)
        ciphertext2 = cipher2.encrypt(plaintext)

        assert ciphertext1 != ciphertext2


class TestTwofishOFB:
    """Tests for TwofishOFB class."""

    def test_valid_key_and_iv(self) -> None:
        """Test that valid key and IV are accepted."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        cipher = TwofishOFB(key, iv)
        assert cipher is not None

    def test_invalid_iv_size(self) -> None:
        """Test that invalid IV sizes raise ValueError."""
        key = b"\x00" * 16

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            TwofishOFB(key, b"\x00" * 8)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test OFB encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher1 = TwofishOFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        # OFB mode: output same length as input
        assert len(ciphertext) == len(plaintext)

        cipher2 = TwofishOFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_no_padding_needed(self) -> None:
        """Test that OFB mode doesn't require padding."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        for length in [1, 7, 15, 17, 100]:
            plaintext = b"x" * length

            cipher1 = TwofishOFB(key, iv)
            ciphertext = cipher1.encrypt(plaintext)
            assert len(ciphertext) == length

            cipher2 = TwofishOFB(key, iv)
            decrypted = cipher2.decrypt(ciphertext)
            assert decrypted == plaintext

    def test_empty_plaintext(self) -> None:
        """Test encrypting empty plaintext."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        cipher = TwofishOFB(key, iv)
        ciphertext = cipher.encrypt(b"")

        assert ciphertext == b""

    def test_different_ivs_produce_different_ciphertext(self) -> None:
        """Test that different IVs produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher1 = TwofishOFB(key, b"\x00" * 16)
        ciphertext1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishOFB(key, b"\xff" * 16)
        ciphertext2 = cipher2.encrypt(plaintext)

        assert ciphertext1 != ciphertext2

    def test_encrypt_decrypt_symmetry(self) -> None:
        """Test that encryption and decryption are the same operation in OFB mode."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Test symmetry!"

        cipher1 = TwofishOFB(key, iv)
        result1 = cipher1.encrypt(plaintext)

        cipher2 = TwofishOFB(key, iv)
        result2 = cipher2.decrypt(plaintext)

        # In OFB mode, encrypt and decrypt should produce the same result
        assert result1 == result2


class TestAllKeyLengths:
    """Test all modes with all supported key lengths."""

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_ecb_key_lengths(self, key_len: int) -> None:
        """Test ECB mode with various key lengths."""
        key = b"\x00" * key_len
        plaintext = b"\x00" * 16

        cipher = TwofishECB(key)
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_cbc_key_lengths(self, key_len: int) -> None:
        """Test CBC mode with various key lengths."""
        key = b"\x00" * key_len
        iv = b"\x00" * 16
        plaintext = b"Test message"

        cipher1 = TwofishCBC(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCBC(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_ctr_key_lengths(self, key_len: int) -> None:
        """Test CTR mode with various key lengths."""
        key = b"\x00" * key_len
        nonce = b"\x00" * 16
        plaintext = b"Test message"

        cipher1 = TwofishCTR(key, nonce)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCTR(key, nonce)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_cfb_key_lengths(self, key_len: int) -> None:
        """Test CFB mode with various key lengths."""
        key = b"\x00" * key_len
        iv = b"\x00" * 16
        plaintext = b"Test message"

        cipher1 = TwofishCFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishCFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_ofb_key_lengths(self, key_len: int) -> None:
        """Test OFB mode with various key lengths."""
        key = b"\x00" * key_len
        iv = b"\x00" * 16
        plaintext = b"Test message"

        cipher1 = TwofishOFB(key, iv)
        ciphertext = cipher1.encrypt(plaintext)

        cipher2 = TwofishOFB(key, iv)
        decrypted = cipher2.decrypt(ciphertext)

        assert decrypted == plaintext
