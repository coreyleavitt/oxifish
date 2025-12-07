"""Type stubs for oxifish - Python bindings for Twofish block cipher."""

from enum import IntEnum, StrEnum
from typing import Final

# Constants
BLOCK_SIZE: Final[int]

# Enums
class BlockSize(IntEnum):
    """Block size enum (Twofish uses 128-bit blocks)."""

    BITS_128 = 16

class KeySize(IntEnum):
    """Valid key sizes for Twofish."""

    BITS_128 = 16
    BITS_192 = 24
    BITS_256 = 32

class PaddingStyle(StrEnum):
    """Padding schemes for block cipher modes."""

    Pkcs7 = "pkcs7"
    Zeros = "zeros"
    Iso7816 = "iso7816"
    AnsiX923 = "ansix923"

# Standalone padding functions
def pad(data: bytes, block_size: int = ..., style: str | PaddingStyle = ...) -> bytes:
    """Pad data to a multiple of block_size.

    Args:
        data: Data to pad
        block_size: Block size in bytes (default: 16)
        style: Padding style (default: Pkcs7)

    Returns:
        Padded data
    """
    ...

def unpad(data: bytes, block_size: int = ..., style: str | PaddingStyle = ...) -> bytes:
    """Remove padding from data.

    Args:
        data: Padded data
        block_size: Block size in bytes (default: 16)
        style: Padding style (default: Pkcs7)

    Returns:
        Unpadded data

    Raises:
        ValueError: If padding is invalid
    """
    ...

# ECB Mode
class TwofishECB:
    """Twofish block cipher in ECB mode (single block operations only)."""

    @property
    def block_size(self) -> BlockSize: ...
    @property
    def key_size(self) -> KeySize: ...
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

# CBC Mode
class TwofishCBCEncryptor:
    """Streaming CBC encryptor. Obtain via TwofishCBC.encryptor()."""

    def update(self, data: bytes) -> bytes:
        """Encrypt data. Data must be block-aligned (16 bytes)."""
        ...

class TwofishCBCDecryptor:
    """Streaming CBC decryptor. Obtain via TwofishCBC.decryptor()."""

    def update(self, data: bytes) -> bytes:
        """Decrypt data. Data must be block-aligned (16 bytes)."""
        ...

class TwofishCBC:
    """Twofish block cipher in CBC mode."""

    @property
    def block_size(self) -> BlockSize: ...
    @property
    def key_size(self) -> KeySize: ...
    def __init__(self, key: bytes) -> None:
        """Create a new TwofishCBC cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        ...

    def encryptor(self, iv: bytes) -> TwofishCBCEncryptor:
        """Create a streaming encryptor.

        Args:
            iv: Initialization vector (16 bytes)

        Raises:
            ValueError: If IV is not 16 bytes
        """
        ...

    def decryptor(self, iv: bytes) -> TwofishCBCDecryptor:
        """Create a streaming decryptor.

        Args:
            iv: Initialization vector (16 bytes)

        Raises:
            ValueError: If IV is not 16 bytes
        """
        ...

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        """Encrypt data (one-shot). Data must be block-aligned. Use pad() first.

        Args:
            data: Plaintext (must be multiple of 16 bytes)
            iv: Initialization vector (16 bytes)

        Returns:
            Ciphertext

        Raises:
            ValueError: If data is not block-aligned or IV is invalid
        """
        ...

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        """Decrypt data (one-shot). Use unpad() on result if padding was used.

        Args:
            data: Ciphertext (must be multiple of 16 bytes)
            iv: Initialization vector (16 bytes)

        Returns:
            Plaintext

        Raises:
            ValueError: If data is not block-aligned or IV is invalid
        """
        ...

# CTR Mode
class TwofishCTRCipher:
    """Streaming CTR cipher. Obtain via TwofishCTR.encryptor() or .decryptor()."""

    def update(self, data: bytes) -> bytes:
        """Encrypt/decrypt data."""
        ...

class TwofishCTR:
    """Twofish block cipher in CTR mode (stream cipher, no padding needed)."""

    @property
    def block_size(self) -> BlockSize: ...
    @property
    def key_size(self) -> KeySize: ...
    def __init__(self, key: bytes) -> None:
        """Create a new TwofishCTR cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        ...

    def encryptor(self, nonce: bytes) -> TwofishCTRCipher:
        """Create a streaming cipher.

        Args:
            nonce: Nonce (16 bytes)

        Raises:
            ValueError: If nonce is not 16 bytes
        """
        ...

    def decryptor(self, nonce: bytes) -> TwofishCTRCipher:
        """Create a streaming cipher (same as encryptor for CTR).

        Args:
            nonce: Nonce (16 bytes)

        Raises:
            ValueError: If nonce is not 16 bytes
        """
        ...

    def encrypt(self, data: bytes, nonce: bytes) -> bytes:
        """Encrypt data (one-shot).

        Args:
            data: Plaintext (any length)
            nonce: Nonce (16 bytes)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes, nonce: bytes) -> bytes:
        """Decrypt data (one-shot).

        Args:
            data: Ciphertext (any length)
            nonce: Nonce (16 bytes)

        Returns:
            Plaintext (same length as input)
        """
        ...

# CFB Mode
class TwofishCFBEncryptor:
    """Streaming CFB encryptor. Obtain via TwofishCFB.encryptor()."""

    def update(self, data: bytes) -> bytes:
        """Encrypt data."""
        ...

class TwofishCFBDecryptor:
    """Streaming CFB decryptor. Obtain via TwofishCFB.decryptor()."""

    def update(self, data: bytes) -> bytes:
        """Decrypt data."""
        ...

class TwofishCFB:
    """Twofish block cipher in CFB mode (stream cipher, no padding needed)."""

    @property
    def block_size(self) -> BlockSize: ...
    @property
    def key_size(self) -> KeySize: ...
    def __init__(self, key: bytes) -> None:
        """Create a new TwofishCFB cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        ...

    def encryptor(self, iv: bytes) -> TwofishCFBEncryptor:
        """Create a streaming encryptor.

        Args:
            iv: Initialization vector (16 bytes)
        """
        ...

    def decryptor(self, iv: bytes) -> TwofishCFBDecryptor:
        """Create a streaming decryptor.

        Args:
            iv: Initialization vector (16 bytes)
        """
        ...

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        """Encrypt data (one-shot).

        Args:
            data: Plaintext (any length)
            iv: Initialization vector (16 bytes)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        """Decrypt data (one-shot).

        Args:
            data: Ciphertext (any length)
            iv: Initialization vector (16 bytes)

        Returns:
            Plaintext (same length as input)
        """
        ...

# OFB Mode
class TwofishOFBCipher:
    """Streaming OFB cipher. Obtain via TwofishOFB.encryptor() or .decryptor()."""

    def update(self, data: bytes) -> bytes:
        """Encrypt/decrypt data."""
        ...

class TwofishOFB:
    """Twofish block cipher in OFB mode (stream cipher, no padding needed)."""

    @property
    def block_size(self) -> BlockSize: ...
    @property
    def key_size(self) -> KeySize: ...
    def __init__(self, key: bytes) -> None:
        """Create a new TwofishOFB cipher.

        Args:
            key: Encryption key (16, 24, or 32 bytes)

        Raises:
            ValueError: If key length is invalid
        """
        ...

    def encryptor(self, iv: bytes) -> TwofishOFBCipher:
        """Create a streaming cipher.

        Args:
            iv: Initialization vector (16 bytes)
        """
        ...

    def decryptor(self, iv: bytes) -> TwofishOFBCipher:
        """Create a streaming cipher (same as encryptor for OFB).

        Args:
            iv: Initialization vector (16 bytes)
        """
        ...

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        """Encrypt data (one-shot).

        Args:
            data: Plaintext (any length)
            iv: Initialization vector (16 bytes)

        Returns:
            Ciphertext (same length as input)
        """
        ...

    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        """Decrypt data (one-shot).

        Args:
            data: Ciphertext (any length)
            iv: Initialization vector (16 bytes)

        Returns:
            Plaintext (same length as input)
        """
        ...

__all__ = [
    # Constants
    "BLOCK_SIZE",
    # Enums
    "BlockSize",
    "KeySize",
    "PaddingStyle",
    # Padding functions
    "pad",
    "unpad",
    # Cipher classes
    "TwofishECB",
    "TwofishCBC",
    "TwofishCTR",
    "TwofishCFB",
    "TwofishOFB",
    # Streaming classes
    "TwofishCBCEncryptor",
    "TwofishCBCDecryptor",
    "TwofishCTRCipher",
    "TwofishCFBEncryptor",
    "TwofishCFBDecryptor",
    "TwofishOFBCipher",
]
