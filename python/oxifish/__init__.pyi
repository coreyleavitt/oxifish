"""Type stubs for oxifish."""

from typing import Final

BLOCK_SIZE: Final[int]

def block_size() -> int:
    """Return the Twofish block size (16 bytes)."""
    ...

class TwofishECB:
    """Twofish block cipher in ECB mode.

    ECB mode encrypts each block independently. This mode does NOT provide
    semantic security and should only be used as a building block for other
    modes or for compatibility with existing systems.
    """

    def __init__(self, key: bytes) -> None:
        """Create a new TwofishECB cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        ...

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block.

        Args:
            block: 16-byte plaintext block

        Returns:
            16-byte ciphertext block

        Raises:
            ValueError: If block is not exactly 16 bytes
        """
        ...

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 16-byte block.

        Args:
            block: 16-byte ciphertext block

        Returns:
            16-byte plaintext block

        Raises:
            ValueError: If block is not exactly 16 bytes
        """
        ...

class TwofishCBC:
    """Twofish block cipher in CBC mode with PKCS7 padding.

    CBC (Cipher Block Chaining) mode provides semantic security when used
    with a unique IV for each encryption operation. This implementation
    uses PKCS7 padding automatically.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        """Create a new TwofishCBC cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)

        Raises:
            ValueError: If key or IV length is invalid
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with PKCS7 padding.

        Args:
            data: Plaintext data (any length)

        Returns:
            Ciphertext (padded to block size multiple)
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data and remove PKCS7 padding.

        Args:
            data: Ciphertext (must be multiple of 16 bytes)

        Returns:
            Decrypted plaintext with padding removed

        Raises:
            ValueError: If data length is invalid or padding is corrupt
        """
        ...
