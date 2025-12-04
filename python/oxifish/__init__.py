"""Python bindings for the RustCrypto Twofish block cipher implementation.

This package provides Twofish encryption in ECB and CBC modes, wrapping the
RustCrypto `twofish` crate via PyO3.

Example:
    >>> from oxifish import TwofishCBC
    >>> key = b'0123456789abcdef'  # 16, 24, or 32 bytes
    >>> iv = b'fedcba9876543210'   # 16 bytes
    >>> cipher = TwofishCBC(key, iv)
    >>> ciphertext = cipher.encrypt(b'Hello, World!')
    >>> cipher2 = TwofishCBC(key, iv)
    >>> plaintext = cipher2.decrypt(ciphertext)
    >>> plaintext
    b'Hello, World!'

Security Note:
    The Twofish algorithm uses key-dependent S-boxes, which means this
    implementation is NOT constant-time and may be vulnerable to cache
    timing attacks. This is an inherent property of Twofish, not a flaw
    in this implementation. For new applications, consider using AES
    (with hardware acceleration) or ChaCha20 instead.
"""

from oxifish._oxifish import BLOCK_SIZE, TwofishCBC, TwofishECB, block_size

__all__ = [
    "TwofishECB",
    "TwofishCBC",
    "BLOCK_SIZE",
    "block_size",
]

__version__ = "0.1.0"
