"""Type stubs for oxifish."""

from enum import IntEnum
from typing import Final

BLOCK_SIZE: Final[int]

def block_size() -> int:
    """Return the Twofish block size (16 bytes)."""
    ...

class Padding(IntEnum):
    """Padding schemes for block cipher modes."""

    Pkcs7 = 0
    """PKCS7 padding (RFC 5652). Each padding byte equals the number of padding bytes."""

    NoPadding = 1
    """No padding. Data must be a multiple of the block size (16 bytes)."""

    Zeros = 2
    """Zero padding. Pads with zero bytes. Ambiguous if plaintext ends with zeros."""

    Iso7816 = 3
    """ISO/IEC 7816-4 padding. Pads with 0x80 followed by zero bytes."""

    AnsiX923 = 4
    """ANSI X9.23 padding. Pads with zeros, last byte is the padding length."""

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
    """Twofish block cipher in CBC mode.

    CBC (Cipher Block Chaining) mode provides semantic security when used
    with a unique IV for each encryption operation.
    """

    def __init__(
        self, key: bytes, iv: bytes, padding: Padding = Padding.Pkcs7
    ) -> None:
        """Create a new TwofishCBC cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)
            padding: Padding scheme (default: Pkcs7)

        Raises:
            ValueError: If key or IV length is invalid
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data.

        Args:
            data: Plaintext data. Must be block-aligned if padding is None.

        Returns:
            Ciphertext

        Raises:
            ValueError: If padding is None and data is not block-aligned
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data.

        Args:
            data: Ciphertext (must be multiple of 16 bytes)

        Returns:
            Decrypted plaintext with padding removed (if applicable)

        Raises:
            ValueError: If data length is invalid or padding is corrupt
        """
        ...

class TwofishCTR:
    """Twofish block cipher in CTR mode.

    CTR (Counter) mode turns a block cipher into a stream cipher. It does not
    require padding and can encrypt data of any length. Each encryption must
    use a unique nonce/IV combination.
    """

    def __init__(self, key: bytes, nonce: bytes) -> None:
        """Create a new TwofishCTR cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)
            nonce: Nonce/IV (16 bytes)

        Raises:
            ValueError: If key or nonce length is invalid
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data.

        Args:
            data: Plaintext data (any length)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data.

        Args:
            data: Ciphertext (any length)

        Returns:
            Plaintext (same length as input)

        Note:
            In CTR mode, encryption and decryption are the same operation.
        """
        ...

class TwofishCFB:
    """Twofish block cipher in CFB mode.

    CFB (Cipher Feedback) mode turns a block cipher into a self-synchronizing
    stream cipher. It does not require padding.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        """Create a new TwofishCFB cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)

        Raises:
            ValueError: If key or IV length is invalid
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data.

        Args:
            data: Plaintext data (any length)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data.

        Args:
            data: Ciphertext (any length)

        Returns:
            Plaintext (same length as input)
        """
        ...

class TwofishOFB:
    """Twofish block cipher in OFB mode.

    OFB (Output Feedback) mode turns a block cipher into a synchronous
    stream cipher. It does not require padding.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        """Create a new TwofishOFB cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)

        Raises:
            ValueError: If key or IV length is invalid
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data.

        Args:
            data: Plaintext data (any length)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data.

        Args:
            data: Ciphertext (any length)

        Returns:
            Plaintext (same length as input)

        Note:
            In OFB mode, encryption and decryption are the same operation.
        """
        ...
