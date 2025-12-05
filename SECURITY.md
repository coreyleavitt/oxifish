# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities by emailing the maintainers directly rather than opening a public issue. We will acknowledge receipt within 48 hours.

## Security Features

### Key Zeroization

All cipher modes (CBC, CTR, CFB, OFB) automatically zeroize keys and IVs from memory when the cipher object is dropped. This uses the `zeroize` crate to prevent compiler optimization from skipping the clear.

**Note**: Python's garbage collector controls when objects are dropped. For sensitive applications, keep cipher object scope narrow and avoid storing keys in long-lived variables.

## Known Limitations

- **Not constant-time**: Twofish uses key-dependent S-boxes. This is suitable for local file decryption (KeePass databases) but not for server-side encryption where timing attacks are feasible.
- **ECB mode**: Provided for compatibility only. Use CBC or CTR for actual encryption.

For details on Twofish's security properties, see the [RustCrypto twofish crate](https://github.com/RustCrypto/block-ciphers/tree/master/twofish).

## Build Security

Wheels are built via GitHub Actions and published to PyPI using OIDC trusted publishing (no stored API tokens).
