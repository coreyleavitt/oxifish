//! Python bindings for the RustCrypto Twofish block cipher.
//!
//! This crate provides Python bindings via PyO3 for the Twofish block cipher,
//! wrapping the RustCrypto `twofish` crate. It supports ECB and CBC modes.

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use cipher::{BlockEncrypt, BlockDecrypt};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use twofish::Twofish;
use zeroize::Zeroize;

const BLOCK_SIZE: usize = 16;

type TwofishCbcEnc = cbc::Encryptor<Twofish>;
type TwofishCbcDec = cbc::Decryptor<Twofish>;

/// Twofish block cipher in ECB mode.
///
/// ECB mode encrypts each block independently. This mode does NOT provide
/// semantic security and should only be used as a building block for other
/// modes or for compatibility with existing systems.
#[pyclass]
struct TwofishECB {
    cipher: Twofish,
}

#[pymethods]
impl TwofishECB {
    /// Create a new TwofishECB cipher.
    ///
    /// Args:
    ///     key: Encryption key (16, 24, or 32 bytes)
    ///
    /// Raises:
    ///     ValueError: If key length is invalid
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        let cipher = Twofish::new_from_slice(key)
            .map_err(|e| PyValueError::new_err(format!("Invalid key: {}", e)))?;
        Ok(Self { cipher })
    }

    /// Encrypt a single 16-byte block.
    ///
    /// Args:
    ///     block: 16-byte plaintext block
    ///
    /// Returns:
    ///     16-byte ciphertext block
    ///
    /// Raises:
    ///     ValueError: If block is not exactly 16 bytes
    fn encrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE {
            return Err(PyValueError::new_err(format!(
                "Block must be {} bytes, got {}",
                BLOCK_SIZE,
                block.len()
            )));
        }
        let mut output = [0u8; BLOCK_SIZE];
        output.copy_from_slice(block);
        self.cipher.encrypt_block((&mut output).into());
        Ok(PyBytes::new_bound(py, &output))
    }

    /// Decrypt a single 16-byte block.
    ///
    /// Args:
    ///     block: 16-byte ciphertext block
    ///
    /// Returns:
    ///     16-byte plaintext block
    ///
    /// Raises:
    ///     ValueError: If block is not exactly 16 bytes
    fn decrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE {
            return Err(PyValueError::new_err(format!(
                "Block must be {} bytes, got {}",
                BLOCK_SIZE,
                block.len()
            )));
        }
        let mut output = [0u8; BLOCK_SIZE];
        output.copy_from_slice(block);
        self.cipher.decrypt_block((&mut output).into());
        Ok(PyBytes::new_bound(py, &output))
    }
}

/// Twofish block cipher in CBC mode with PKCS7 padding.
///
/// CBC (Cipher Block Chaining) mode provides semantic security when used
/// with a unique IV for each encryption operation. This implementation
/// uses PKCS7 padding automatically.
#[pyclass]
struct TwofishCBC {
    key: Vec<u8>,
    iv: Vec<u8>,
}

#[pymethods]
impl TwofishCBC {
    /// Create a new TwofishCBC cipher.
    ///
    /// Args:
    ///     key: Encryption key (16, 24, or 32 bytes)
    ///     iv: Initialization vector (16 bytes)
    ///
    /// Raises:
    ///     ValueError: If key or IV length is invalid
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        if iv.len() != BLOCK_SIZE {
            return Err(PyValueError::new_err(format!(
                "IV must be {} bytes, got {}",
                BLOCK_SIZE,
                iv.len()
            )));
        }
        Ok(Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
        })
    }

    /// Encrypt data with PKCS7 padding.
    ///
    /// Args:
    ///     data: Plaintext data (any length)
    ///
    /// Returns:
    ///     Ciphertext (padded to block size multiple)
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut buffer = pkcs7_pad(data);
        let len = buffer.len();
        let encryptor = TwofishCbcEnc::new_from_slices(&self.key, &self.iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        encryptor.encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, len)
            .map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Decrypt data and remove PKCS7 padding.
    ///
    /// Args:
    ///     data: Ciphertext (must be multiple of 16 bytes)
    ///
    /// Returns:
    ///     Decrypted plaintext with padding removed
    ///
    /// Raises:
    ///     ValueError: If data length is invalid or padding is corrupt
    fn decrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
            return Err(PyValueError::new_err(format!(
                "Ciphertext must be non-empty and multiple of {} bytes, got {}",
                BLOCK_SIZE,
                data.len()
            )));
        }
        let decryptor = TwofishCbcDec::new_from_slices(&self.key, &self.iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        decryptor
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
            .map_err(|e| PyRuntimeError::new_err(format!("Decryption failed: {}", e)))?;

        let plaintext = pkcs7_unpad(&buffer)?;
        Ok(PyBytes::new_bound(py, plaintext))
    }
}

impl Drop for TwofishCBC {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Validate key length for Twofish (16, 24, or 32 bytes).
fn validate_key_length(len: usize) -> PyResult<()> {
    if len != 16 && len != 24 && len != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits), got {} bytes",
            len
        )));
    }
    Ok(())
}

/// Apply PKCS7 padding to data.
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

/// Remove and validate PKCS7 padding.
fn pkcs7_unpad(data: &[u8]) -> PyResult<&[u8]> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Cannot unpad empty data"));
    }

    let padding_len = data[data.len() - 1] as usize;

    if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > data.len() {
        return Err(PyValueError::new_err("Invalid PKCS7 padding"));
    }

    // Validate all padding bytes
    for &byte in &data[data.len() - padding_len..] {
        if byte as usize != padding_len {
            return Err(PyValueError::new_err("Invalid PKCS7 padding"));
        }
    }

    Ok(&data[..data.len() - padding_len])
}

/// Block size constant (16 bytes / 128 bits)
#[pyfunction]
const fn block_size() -> usize {
    BLOCK_SIZE
}

/// Python module definition
#[pymodule]
fn _oxifish(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TwofishECB>()?;
    m.add_class::<TwofishCBC>()?;
    m.add_function(wrap_pyfunction!(block_size, m)?)?;
    m.add("BLOCK_SIZE", BLOCK_SIZE)?;
    Ok(())
}
