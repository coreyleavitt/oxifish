"""Python bindings for the RustCrypto Twofish block cipher implementation.

This package provides Twofish encryption in multiple modes (ECB, CBC, CTR, CFB, OFB),
wrapping the RustCrypto `twofish` crate via PyO3.

Example:
    >>> from oxifish import TwofishCBC, Padding
    >>> key = b'0123456789abcdef'  # 16, 24, or 32 bytes
    >>> iv = b'fedcba9876543210'   # 16 bytes
    >>> cipher = TwofishCBC(key, iv, Padding.Pkcs7)
    >>> ciphertext = cipher.encrypt(b'Hello, World!')
    >>> cipher2 = TwofishCBC(key, iv, Padding.Pkcs7)
    >>> plaintext = cipher2.decrypt(ciphertext)
    >>> plaintext
    b'Hello, World!'

Available Modes:
    - TwofishECB: Electronic Codebook (single block operations)
    - TwofishCBC: Cipher Block Chaining (requires padding)
    - TwofishCTR: Counter mode (stream cipher, no padding needed)
    - TwofishCFB: Cipher Feedback (stream cipher, no padding needed)
    - TwofishOFB: Output Feedback (stream cipher, no padding needed)

Padding Options (for CBC mode):
    - Padding.Pkcs7: PKCS7 padding (default, most common)
    - Padding.NoPadding: No padding (data must be block-aligned)
    - Padding.Zeros: Zero padding (ambiguous if plaintext ends with zeros)
    - Padding.Iso7816: ISO/IEC 7816-4 padding
    - Padding.AnsiX923: ANSI X9.23 padding

Security Note:
    The Twofish algorithm uses key-dependent S-boxes, which means this
    implementation is NOT constant-time and may be vulnerable to cache
    timing attacks. This is an inherent property of Twofish, not a flaw
    in this implementation. For new applications, consider using AES
    (with hardware acceleration) or ChaCha20 instead.
"""

from oxifish._oxifish import (
    BLOCK_SIZE,
    Padding,
    TwofishCBC,
    TwofishCFB,
    TwofishCTR,
    TwofishECB,
    TwofishOFB,
    block_size,
)

__all__ = [
    "Padding",
    "TwofishECB",
    "TwofishCBC",
    "TwofishCTR",
    "TwofishCFB",
    "TwofishOFB",
    "BLOCK_SIZE",
    "block_size",
]

__version__ = "0.1.0"
