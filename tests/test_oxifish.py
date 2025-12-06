"""Tests for oxifish Twofish implementation."""

import pytest
from oxifish import (
    BLOCK_SIZE,
    BlockSize,
    KeySize,
    PaddingStyle,
    TwofishCBC,
    TwofishCFB,
    TwofishCTR,
    TwofishECB,
    TwofishOFB,
    pad,
    unpad,
)


class TestEnums:
    """Tests for enum types."""

    def test_block_size_enum(self) -> None:
        """Test BlockSize enum values."""
        assert int(BlockSize.BITS_128) == 16

    def test_key_size_enum(self) -> None:
        """Test KeySize enum values."""
        assert int(KeySize.BITS_128) == 16
        assert int(KeySize.BITS_192) == 24
        assert int(KeySize.BITS_256) == 32

    def test_padding_style_enum(self) -> None:
        """Test PaddingStyle enum."""
        assert str(PaddingStyle.Pkcs7) == "pkcs7"
        assert str(PaddingStyle.Zeros) == "zeros"
        assert str(PaddingStyle.Iso7816) == "iso7816"
        assert str(PaddingStyle.AnsiX923) == "ansix923"

    def test_block_size_constant(self) -> None:
        """Test BLOCK_SIZE constant is 16."""
        assert BLOCK_SIZE == 16


class TestPadding:
    """Tests for standalone padding functions."""

    def test_pkcs7_pad_unpad(self) -> None:
        """Test PKCS7 padding roundtrip."""
        data = b"Hello!"
        padded = pad(data, 16, PaddingStyle.Pkcs7)
        assert len(padded) == 16
        unpadded = unpad(padded, 16, PaddingStyle.Pkcs7)
        assert unpadded == data

    def test_pkcs7_full_block_padding(self) -> None:
        """Test PKCS7 adds full block when data is block-aligned."""
        data = b"0123456789abcdef"  # Exactly 16 bytes
        padded = pad(data, 16, PaddingStyle.Pkcs7)
        assert len(padded) == 32  # Full block of padding added
        unpadded = unpad(padded, 16, PaddingStyle.Pkcs7)
        assert unpadded == data

    def test_zeros_pad_unpad(self) -> None:
        """Test zero padding roundtrip."""
        data = b"Hello!"
        padded = pad(data, 16, PaddingStyle.Zeros)
        assert len(padded) == 16
        unpadded = unpad(padded, 16, PaddingStyle.Zeros)
        assert unpadded == data

    def test_zeros_no_padding_when_aligned(self) -> None:
        """Test zero padding adds nothing when block-aligned."""
        data = b"0123456789abcdef"
        padded = pad(data, 16, PaddingStyle.Zeros)
        assert padded == data

    def test_iso7816_pad_unpad(self) -> None:
        """Test ISO 7816-4 padding roundtrip."""
        data = b"Hello!"
        padded = pad(data, 16, PaddingStyle.Iso7816)
        assert len(padded) == 16
        assert padded[6] == 0x80  # Marker byte
        unpadded = unpad(padded, 16, PaddingStyle.Iso7816)
        assert unpadded == data

    def test_ansix923_pad_unpad(self) -> None:
        """Test ANSI X9.23 padding roundtrip."""
        data = b"Hello!"
        padded = pad(data, 16, PaddingStyle.AnsiX923)
        assert len(padded) == 16
        assert padded[-1] == 10  # Padding length
        unpadded = unpad(padded, 16, PaddingStyle.AnsiX923)
        assert unpadded == data

    def test_invalid_pkcs7_padding(self) -> None:
        """Test that invalid PKCS7 padding raises error."""
        invalid = b"Hello!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"
        with pytest.raises(ValueError, match="Invalid PKCS7"):
            unpad(invalid, 16, PaddingStyle.Pkcs7)

    def test_empty_data_unpad_error(self) -> None:
        """Test that unpadding empty data raises error."""
        with pytest.raises(ValueError, match="Cannot unpad empty"):
            unpad(b"", 16, PaddingStyle.Pkcs7)


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

    def test_block_size_property(self) -> None:
        """Test block_size property."""
        cipher = TwofishECB(b"\x00" * 16)
        assert cipher.block_size == BlockSize.BITS_128
        assert cipher.block_size == 16

    def test_key_size_property(self) -> None:
        """Test key_size property."""
        assert TwofishECB(b"\x00" * 16).key_size == KeySize.BITS_128
        assert TwofishECB(b"\x00" * 24).key_size == KeySize.BITS_192
        assert TwofishECB(b"\x00" * 32).key_size == KeySize.BITS_256

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

    # Official Twofish test vectors
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

    def test_valid_key(self) -> None:
        """Test that valid keys are accepted."""
        cipher = TwofishCBC(b"\x00" * 16)
        assert cipher is not None

    def test_block_size_property(self) -> None:
        """Test block_size property."""
        cipher = TwofishCBC(b"\x00" * 16)
        assert cipher.block_size == 16

    def test_key_size_property(self) -> None:
        """Test key_size property."""
        assert TwofishCBC(b"\x00" * 16).key_size == KeySize.BITS_128
        assert TwofishCBC(b"\x00" * 32).key_size == KeySize.BITS_256

    def test_invalid_iv_size(self) -> None:
        """Test that invalid IV sizes raise ValueError."""
        cipher = TwofishCBC(b"\x00" * 16)

        with pytest.raises(ValueError, match="IV/nonce must be 16 bytes"):
            cipher.encrypt(b"\x00" * 16, b"\x00" * 8)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CBC encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher = TwofishCBC(key)
        padded = pad(plaintext, 16, PaddingStyle.Pkcs7)
        ciphertext = cipher.encrypt(padded, iv)

        assert len(ciphertext) == 16

        decrypted = cipher.decrypt(ciphertext, iv)
        unpadded = unpad(decrypted, 16, PaddingStyle.Pkcs7)

        assert unpadded == plaintext

    def test_encrypt_decrypt_multi_block(self) -> None:
        """Test CBC with multiple blocks."""
        key = b"\x00" * 32
        iv = b"\x00" * 16
        plaintext = b"A" * 100

        cipher = TwofishCBC(key)
        padded = pad(plaintext, 16, PaddingStyle.Pkcs7)
        ciphertext = cipher.encrypt(padded, iv)

        assert len(ciphertext) == 112  # 7 blocks

        decrypted = cipher.decrypt(ciphertext, iv)
        unpadded = unpad(decrypted, 16, PaddingStyle.Pkcs7)

        assert unpadded == plaintext

    def test_data_must_be_block_aligned(self) -> None:
        """Test that non-aligned data raises error."""
        cipher = TwofishCBC(b"\x00" * 16)
        iv = b"\x00" * 16

        with pytest.raises(ValueError, match="must be a multiple of 16"):
            cipher.encrypt(b"not aligned", iv)

    def test_different_ivs_produce_different_ciphertext(self) -> None:
        """Test that different IVs produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = pad(b"Same plaintext!!", 16)

        cipher = TwofishCBC(key)
        ciphertext1 = cipher.encrypt(plaintext, b"\x00" * 16)
        ciphertext2 = cipher.encrypt(plaintext, b"\xff" * 16)

        assert ciphertext1 != ciphertext2

    def test_streaming_encryptor(self) -> None:
        """Test streaming encryption."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"A" * 32  # 2 blocks

        cipher = TwofishCBC(key)

        # Streaming
        enc = cipher.encryptor(iv)
        ct1 = enc.update(plaintext[:16])
        ct2 = enc.update(plaintext[16:])
        enc.finalize()
        streaming_ct = ct1 + ct2

        # One-shot
        oneshot_ct = cipher.encrypt(plaintext, iv)

        assert streaming_ct == oneshot_ct

    def test_streaming_decryptor(self) -> None:
        """Test streaming decryption."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"A" * 32

        cipher = TwofishCBC(key)
        ciphertext = cipher.encrypt(plaintext, iv)

        # Streaming decrypt
        dec = cipher.decryptor(iv)
        pt1 = dec.update(ciphertext[:16])
        pt2 = dec.update(ciphertext[16:])
        dec.finalize()

        assert pt1 + pt2 == plaintext


class TestTwofishCTR:
    """Tests for TwofishCTR class."""

    def test_valid_key(self) -> None:
        """Test that valid keys are accepted."""
        cipher = TwofishCTR(b"\x00" * 16)
        assert cipher is not None

    def test_properties(self) -> None:
        """Test block_size and key_size properties."""
        cipher = TwofishCTR(b"\x00" * 16)
        assert cipher.block_size == 16
        assert cipher.key_size == KeySize.BITS_128

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CTR encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        nonce = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher = TwofishCTR(key)
        ciphertext = cipher.encrypt(plaintext, nonce)

        # CTR mode: output same length as input
        assert len(ciphertext) == len(plaintext)

        decrypted = cipher.decrypt(ciphertext, nonce)
        assert decrypted == plaintext

    def test_no_padding_needed(self) -> None:
        """Test that CTR mode doesn't require padding."""
        key = b"\x00" * 16
        nonce = b"\x00" * 16

        cipher = TwofishCTR(key)

        for length in [1, 7, 15, 17, 100]:
            plaintext = b"x" * length
            ciphertext = cipher.encrypt(plaintext, nonce)
            assert len(ciphertext) == length
            decrypted = cipher.decrypt(ciphertext, nonce)
            assert decrypted == plaintext

    def test_different_nonces_produce_different_ciphertext(self) -> None:
        """Test that different nonces produce different ciphertext."""
        key = b"\x00" * 16
        plaintext = b"Same plaintext!!"

        cipher = TwofishCTR(key)
        ciphertext1 = cipher.encrypt(plaintext, b"\x00" * 16)
        ciphertext2 = cipher.encrypt(plaintext, b"\xff" * 16)

        assert ciphertext1 != ciphertext2

    def test_streaming(self) -> None:
        """Test streaming CTR mode."""
        key = b"\x00" * 16
        nonce = b"\x00" * 16
        plaintext = b"Hello, World! This is a test."

        cipher = TwofishCTR(key)

        # Streaming
        enc = cipher.encryptor(nonce)
        ct1 = enc.update(plaintext[:10])
        ct2 = enc.update(plaintext[10:20])
        ct3 = enc.update(plaintext[20:])
        enc.finalize()
        streaming_ct = ct1 + ct2 + ct3

        # One-shot
        oneshot_ct = cipher.encrypt(plaintext, nonce)

        assert streaming_ct == oneshot_ct


class TestTwofishCFB:
    """Tests for TwofishCFB class."""

    def test_valid_key(self) -> None:
        """Test that valid keys are accepted."""
        cipher = TwofishCFB(b"\x00" * 16)
        assert cipher is not None

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test CFB encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher = TwofishCFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)

        assert len(ciphertext) == len(plaintext)

        decrypted = cipher.decrypt(ciphertext, iv)
        assert decrypted == plaintext

    def test_no_padding_needed(self) -> None:
        """Test that CFB mode doesn't require padding."""
        key = b"\x00" * 16
        iv = b"\x00" * 16

        cipher = TwofishCFB(key)

        for length in [1, 7, 15, 17, 100]:
            plaintext = b"x" * length
            ciphertext = cipher.encrypt(plaintext, iv)
            assert len(ciphertext) == length
            decrypted = cipher.decrypt(ciphertext, iv)
            assert decrypted == plaintext


class TestTwofishOFB:
    """Tests for TwofishOFB class."""

    def test_valid_key(self) -> None:
        """Test that valid keys are accepted."""
        cipher = TwofishOFB(b"\x00" * 16)
        assert cipher is not None

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test OFB encrypt/decrypt roundtrip."""
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        plaintext = b"Hello, World!"

        cipher = TwofishOFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)

        assert len(ciphertext) == len(plaintext)

        decrypted = cipher.decrypt(ciphertext, iv)
        assert decrypted == plaintext

    def test_encrypt_decrypt_symmetry(self) -> None:
        """Test that encryption and decryption are the same operation in OFB mode."""
        key = b"\x00" * 16
        iv = b"\x00" * 16
        plaintext = b"Test symmetry!"

        cipher = TwofishOFB(key)
        result1 = cipher.encrypt(plaintext, iv)
        result2 = cipher.decrypt(plaintext, iv)

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
        plaintext = b"\x00" * 16  # Block aligned

        cipher = TwofishCBC(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        decrypted = cipher.decrypt(ciphertext, iv)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_ctr_key_lengths(self, key_len: int) -> None:
        """Test CTR mode with various key lengths."""
        key = b"\x00" * key_len
        nonce = b"\x00" * 16
        plaintext = b"Test message"

        cipher = TwofishCTR(key)
        ciphertext = cipher.encrypt(plaintext, nonce)
        decrypted = cipher.decrypt(ciphertext, nonce)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_cfb_key_lengths(self, key_len: int) -> None:
        """Test CFB mode with various key lengths."""
        key = b"\x00" * key_len
        iv = b"\x00" * 16
        plaintext = b"Test message"

        cipher = TwofishCFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        decrypted = cipher.decrypt(ciphertext, iv)

        assert decrypted == plaintext

    @pytest.mark.parametrize("key_len", [16, 24, 32])
    def test_ofb_key_lengths(self, key_len: int) -> None:
        """Test OFB mode with various key lengths."""
        key = b"\x00" * key_len
        iv = b"\x00" * 16
        plaintext = b"Test message"

        cipher = TwofishOFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        decrypted = cipher.decrypt(ciphertext, iv)

        assert decrypted == plaintext


class TestCrossImplementationVectors:
    """Cross-implementation test vectors verified against twofish Python package.

    These vectors ensure our CBC, CTR, CFB, and OFB implementations match
    other Twofish implementations.
    """

    # Vector 1: All zeros (128-bit key)
    # For all-zeros input, CBC/CTR/CFB/OFB all produce the same output
    # because E(0) XOR 0 = E(0) and E(0 XOR 0) = E(0)
    def test_vector1_128bit_cbc(self) -> None:
        """Test CBC with 128-bit all-zeros vector."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")

        cipher = TwofishCBC(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector1_128bit_ctr(self) -> None:
        """Test CTR with 128-bit all-zeros vector."""
        key = bytes.fromhex("00000000000000000000000000000000")
        nonce = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")

        cipher = TwofishCTR(key)
        ciphertext = cipher.encrypt(plaintext, nonce)
        assert ciphertext == expected

    def test_vector1_128bit_cfb(self) -> None:
        """Test CFB with 128-bit all-zeros vector."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")

        cipher = TwofishCFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector1_128bit_ofb(self) -> None:
        """Test OFB with 128-bit all-zeros vector."""
        key = bytes.fromhex("00000000000000000000000000000000")
        iv = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a")

        cipher = TwofishOFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    # Vector 2: Non-trivial (192-bit key)
    def test_vector2_192bit_cbc(self) -> None:
        """Test CBC with 192-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        iv = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("742ca6db422942b78c47ef6c7db185d8")

        cipher = TwofishCBC(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector2_192bit_ctr(self) -> None:
        """Test CTR with 192-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        nonce = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("4605106ad990fea6659ce93fb8b9a921")

        cipher = TwofishCTR(key)
        ciphertext = cipher.encrypt(plaintext, nonce)
        assert ciphertext == expected

    def test_vector2_192bit_cfb(self) -> None:
        """Test CFB with 192-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        iv = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("4605106ad990fea6659ce93fb8b9a921")

        cipher = TwofishCFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector2_192bit_ofb(self) -> None:
        """Test OFB with 192-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba98765432100011223344556677")
        iv = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("4605106ad990fea6659ce93fb8b9a921")

        cipher = TwofishOFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    # Vector 3: 256-bit key
    def test_vector3_256bit_cbc(self) -> None:
        """Test CBC with 256-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        iv = bytes.fromhex("fedcba9876543210fedcba9876543210")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("8cb4fcbf0d29b43cb760563d68dd0530")

        cipher = TwofishCBC(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector3_256bit_ctr(self) -> None:
        """Test CTR with 256-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        nonce = bytes.fromhex("fedcba9876543210fedcba9876543210")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("894a10bffd09d5937abb9f67bbf43fb9")

        cipher = TwofishCTR(key)
        ciphertext = cipher.encrypt(plaintext, nonce)
        assert ciphertext == expected

    def test_vector3_256bit_cfb(self) -> None:
        """Test CFB with 256-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        iv = bytes.fromhex("fedcba9876543210fedcba9876543210")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("894a10bffd09d5937abb9f67bbf43fb9")

        cipher = TwofishCFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected

    def test_vector3_256bit_ofb(self) -> None:
        """Test OFB with 256-bit key vector."""
        key = bytes.fromhex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")
        iv = bytes.fromhex("fedcba9876543210fedcba9876543210")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("894a10bffd09d5937abb9f67bbf43fb9")

        cipher = TwofishOFB(key)
        ciphertext = cipher.encrypt(plaintext, iv)
        assert ciphertext == expected
