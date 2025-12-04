# oxifish

Python bindings for the [RustCrypto Twofish](https://github.com/RustCrypto/block-ciphers) block cipher implementation.

## Installation

```bash
pip install oxifish
```

## Usage

```python
from oxifish import TwofishCBC

# Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)
key = b'0123456789abcdef'
# IV must be 16 bytes
iv = b'fedcba9876543210'

# Encrypt
cipher = TwofishCBC(key, iv)
ciphertext = cipher.encrypt(b'Hello, World!')

# Decrypt (create new instance with same key/iv)
cipher = TwofishCBC(key, iv)
plaintext = cipher.decrypt(ciphertext)
# b'Hello, World!'
```

### ECB Mode

For low-level block operations (use CBC for actual encryption):

```python
from oxifish import TwofishECB

cipher = TwofishECB(key)
ciphertext = cipher.encrypt_block(b'16 byte block!!')
plaintext = cipher.decrypt_block(ciphertext)
```

## Security Considerations

The Twofish algorithm uses key-dependent S-boxes, which means this implementation is **not constant-time** and may be vulnerable to cache timing attacks in adversarial environments. This is an inherent property of the Twofish algorithm, not a flaw in this implementation.

For new applications where timing attacks are a concern, consider using:
- AES with hardware acceleration (AES-NI)
- ChaCha20

This library is primarily intended for compatibility with existing systems that require Twofish, such as KeePass databases.

## Development

Requires Rust and Python 3.10+.

```bash
# Install uv if you haven't
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create venv and install maturin
uv venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
uv pip install maturin

# Build and install in development mode
maturin develop

# Run tests
uv pip install pytest
pytest
```

## License

MIT License. See [LICENSE](LICENSE) for details.

This project uses the [RustCrypto twofish crate](https://crates.io/crates/twofish) which is dual-licensed under MIT/Apache-2.0. We use it under the MIT license.
