# oxifish

Python bindings for the [RustCrypto Twofish](https://github.com/RustCrypto/block-ciphers) block cipher implementation.

## Installation

```bash
pip install oxifish
```

## Usage

### CBC Mode (with padding)

```python
import secrets
from oxifish import TwofishCBC, Padding

key = secrets.token_bytes(16)  # 16, 24, or 32 bytes
iv = secrets.token_bytes(16)   # MUST be unique per encryption

# Encrypt (PKCS7 padding is the default)
cipher = TwofishCBC(key, iv, Padding.Pkcs7)
ciphertext = cipher.encrypt(b'Hello, World!')

# Decrypt (new instance required - cipher is stateful)
cipher = TwofishCBC(key, iv, Padding.Pkcs7)
plaintext = cipher.decrypt(ciphertext)
# b'Hello, World!'

# Store IV with ciphertext (IV is not secret)
encrypted_message = iv + ciphertext
```

### CTR Mode (no padding needed)

```python
import secrets
from oxifish import TwofishCTR

key = secrets.token_bytes(16)
nonce = secrets.token_bytes(16)  # MUST be unique per encryption

cipher = TwofishCTR(key, nonce)
ciphertext = cipher.encrypt(b'any length data')

cipher = TwofishCTR(key, nonce)
plaintext = cipher.decrypt(ciphertext)
```

### ECB Mode (single blocks only)

```python
import secrets
from oxifish import TwofishECB

key = secrets.token_bytes(16)
cipher = TwofishECB(key)
ciphertext = cipher.encrypt_block(b'16 byte block!!')
plaintext = cipher.decrypt_block(ciphertext)
```

**Warning**: ECB mode does NOT provide semantic security. Use CBC, CTR, or other modes for general encryption.

### Available Modes

| Mode | Padding | Use Case |
|------|---------|----------|
| `TwofishCBC` | Required (Pkcs7, Zeros, Iso7816, AnsiX923, NoPadding) | General encryption |
| `TwofishCTR` | Not needed | Stream encryption |
| `TwofishCFB` | Not needed | Stream encryption |
| `TwofishOFB` | Not needed | Stream encryption |
| `TwofishECB` | N/A (block-level) | Building blocks, compatibility |

## Security

This library is primarily intended for compatibility with existing systems that require Twofish, such as KeePass databases.

**Note**: Twofish is not constant-time due to key-dependent S-boxes. This is fine for local file decryption but not suitable for server-side encryption where timing attacks are feasible. For new projects, prefer AES-GCM or ChaCha20-Poly1305.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and details on key zeroization.

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
