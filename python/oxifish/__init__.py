"""Python bindings for the RustCrypto Twofish block cipher implementation.

This package provides Twofish encryption in multiple modes (ECB, CBC, CTR, CFB, OFB),
wrapping the RustCrypto `twofish` crate via PyO3.

Example (one-shot with padding):
    >>> import secrets
    >>> from oxifish import TwofishCBC, pad, unpad, PaddingStyle
    >>> key = secrets.token_bytes(16)  # 16, 24, or 32 bytes
    >>> iv = secrets.token_bytes(16)   # Must be unique per encryption
    >>> cipher = TwofishCBC(key)
    >>> padded = pad(b'Hello, World!', cipher.block_size, PaddingStyle.Pkcs7)
    >>> ciphertext = cipher.encrypt(padded, iv)
    >>> # Store IV with ciphertext (IV is not secret)
    >>> encrypted_message = iv + ciphertext
    >>> # Decrypt
    >>> plaintext = unpad(cipher.decrypt(ciphertext, iv), cipher.block_size)
    >>> plaintext
    b'Hello, World!'

Example (streaming):
    >>> cipher = TwofishCBC(key)
    >>> enc = cipher.encryptor(iv)
    >>> ct = enc.update(pad(b'chunk1', 16)) + enc.update(pad(b'chunk2', 16))

Available Modes:
    - TwofishECB: Electronic Codebook (single block operations)
    - TwofishCBC: Cipher Block Chaining (use with pad/unpad)
    - TwofishCTR: Counter mode (stream cipher, no padding needed)
    - TwofishCFB: Cipher Feedback (stream cipher, no padding needed)
    - TwofishOFB: Output Feedback (stream cipher, no padding needed)

Padding:
    Use pad() before encryption and unpad() after decryption for CBC mode.
    Stream cipher modes (CTR, CFB, OFB) do not require padding.

Security Note:
    The Twofish algorithm uses key-dependent S-boxes, which means this
    implementation is NOT constant-time and may be vulnerable to cache
    timing attacks. This is an inherent property of Twofish, not a flaw
    in this implementation. For new applications, consider using AES
    (with hardware acceleration) or ChaCha20 instead.
"""

from enum import StrEnum

from oxifish._oxifish import (
    # Constants
    BLOCK_SIZE,
    # Enums
    BlockSize,
    KeySize,
    TwofishCBC,
    TwofishCBCDecryptor,
    # Streaming cipher classes (returned by encryptor/decryptor methods)
    TwofishCBCEncryptor,
    TwofishCFB,
    TwofishCFBDecryptor,
    TwofishCFBEncryptor,
    TwofishCTR,
    TwofishCTRCipher,
    # Cipher classes
    TwofishECB,
    TwofishOFB,
    TwofishOFBCipher,
    # Padding functions
    pad,
    unpad,
)


class PaddingStyle(StrEnum):
    """Padding schemes for block cipher modes.

    - Pkcs7: PKCS#7 padding (RFC 5652) - recommended for most uses
    - Zeros: Zero padding (ambiguous if data ends with zeros)
    - Iso7816: ISO/IEC 7816-4 padding
    - AnsiX923: ANSI X9.23 padding
    """

    Pkcs7 = "pkcs7"
    Zeros = "zeros"
    Iso7816 = "iso7816"
    AnsiX923 = "ansix923"


__all__ = [
    # Enums
    "BlockSize",
    "KeySize",
    "PaddingStyle",
    # Cipher classes
    "TwofishECB",
    "TwofishCBC",
    "TwofishCTR",
    "TwofishCFB",
    "TwofishOFB",
    # Streaming cipher classes
    "TwofishCBCEncryptor",
    "TwofishCBCDecryptor",
    "TwofishCTRCipher",
    "TwofishCFBEncryptor",
    "TwofishCFBDecryptor",
    "TwofishOFBCipher",
    # Padding functions
    "pad",
    "unpad",
    # Constants
    "BLOCK_SIZE",
]

__version__ = "0.1.0"
