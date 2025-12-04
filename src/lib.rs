//! Python bindings for the RustCrypto Twofish block cipher.
//!
//! This crate provides Python bindings via PyO3 for the Twofish block cipher,
//! wrapping the RustCrypto `twofish` crate. It supports ECB, CBC, CTR, CFB, and OFB modes.

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use cipher::{AsyncStreamCipher, BlockDecrypt, BlockEncrypt, InnerIvInit, StreamCipherCore};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use twofish::Twofish;
use zeroize::Zeroize;

const BLOCK_SIZE: usize = 16;

// Type aliases for cipher modes
type TwofishCbcEnc = cbc::Encryptor<Twofish>;
type TwofishCbcDec = cbc::Decryptor<Twofish>;
type TwofishCtrCore = ctr::CtrCore<Twofish, ctr::flavors::Ctr128BE>;
type TwofishCfbEnc = cfb_mode::Encryptor<Twofish>;
type TwofishCfbDec = cfb_mode::Decryptor<Twofish>;
type TwofishOfbCore = ofb::OfbCore<Twofish>;

/// Padding schemes for block cipher modes.
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// PKCS7 padding (RFC 5652). Each padding byte equals the number of padding bytes.
    /// This is the most widely used padding scheme.
    Pkcs7,
    /// No padding. Data must be a multiple of the block size (16 bytes).
    NoPadding,
    /// Zero padding. Pads with zero bytes. Ambiguous if plaintext ends with zeros.
    Zeros,
    /// ISO/IEC 7816-4 padding. Pads with 0x80 followed by zero bytes.
    Iso7816,
    /// ANSI X9.23 padding. Pads with zeros, last byte is the padding length.
    AnsiX923,
}

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

/// Twofish block cipher in CBC mode.
///
/// CBC (Cipher Block Chaining) mode provides semantic security when used
/// with a unique IV for each encryption operation.
#[pyclass]
struct TwofishCBC {
    key: Vec<u8>,
    iv: Vec<u8>,
    padding: Padding,
}

#[pymethods]
impl TwofishCBC {
    /// Create a new TwofishCBC cipher.
    ///
    /// Args:
    ///     key: Encryption key (16, 24, or 32 bytes)
    ///     iv: Initialization vector (16 bytes)
    ///     padding: Padding scheme (default: Pkcs7)
    ///
    /// Raises:
    ///     ValueError: If key or IV length is invalid
    #[new]
    #[pyo3(signature = (key, iv, padding=Padding::Pkcs7))]
    fn new(key: &[u8], iv: &[u8], padding: Padding) -> PyResult<Self> {
        validate_key_length(key.len())?;
        validate_iv_length(iv.len())?;
        Ok(Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
            padding,
        })
    }

    /// Encrypt data.
    ///
    /// Args:
    ///     data: Plaintext data. Must be block-aligned if padding is None.
    ///
    /// Returns:
    ///     Ciphertext
    ///
    /// Raises:
    ///     ValueError: If padding is None and data is not block-aligned
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut buffer = apply_padding(data, self.padding)?;
        let len = buffer.len();
        let encryptor = TwofishCbcEnc::new_from_slices(&self.key, &self.iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        encryptor
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, len)
            .map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Decrypt data.
    ///
    /// Args:
    ///     data: Ciphertext (must be multiple of 16 bytes)
    ///
    /// Returns:
    ///     Decrypted plaintext with padding removed (if applicable)
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

        let plaintext = remove_padding(&buffer, self.padding)?;
        Ok(PyBytes::new_bound(py, plaintext))
    }
}

impl Drop for TwofishCBC {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Twofish block cipher in CTR mode.
///
/// CTR (Counter) mode turns a block cipher into a stream cipher. It does not
/// require padding and can encrypt data of any length. Each encryption must
/// use a unique nonce/IV combination.
#[pyclass]
struct TwofishCTR {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

#[pymethods]
impl TwofishCTR {
    /// Create a new TwofishCTR cipher.
    ///
    /// Args:
    ///     key: Encryption key (16, 24, or 32 bytes)
    ///     nonce: Nonce/IV (16 bytes)
    ///
    /// Raises:
    ///     ValueError: If key or nonce length is invalid
    #[new]
    fn new(key: &[u8], nonce: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        validate_iv_length(nonce.len())?;
        Ok(Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
        })
    }

    /// Encrypt data.
    ///
    /// Args:
    ///     data: Plaintext data (any length)
    ///
    /// Returns:
    ///     Ciphertext (same length as input)
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        // Create Twofish cipher with variable key size, then wrap in CTR mode
        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let nonce = cipher::generic_array::GenericArray::from_slice(&self.nonce);
        let core = TwofishCtrCore::inner_iv_init(twofish, nonce);
        let mut cipher = cipher::StreamCipherCoreWrapper::from_core(core);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Decrypt data.
    ///
    /// Args:
    ///     data: Ciphertext (any length)
    ///
    /// Returns:
    ///     Plaintext (same length as input)
    ///
    /// Note: In CTR mode, encryption and decryption are the same operation.
    fn decrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        // CTR mode: encryption and decryption are identical
        self.encrypt(py, data)
    }
}

impl Drop for TwofishCTR {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

/// Twofish block cipher in CFB mode.
///
/// CFB (Cipher Feedback) mode turns a block cipher into a self-synchronizing
/// stream cipher. It does not require padding.
#[pyclass]
struct TwofishCFB {
    key: Vec<u8>,
    iv: Vec<u8>,
}

#[pymethods]
impl TwofishCFB {
    /// Create a new TwofishCFB cipher.
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
        validate_iv_length(iv.len())?;
        Ok(Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
        })
    }

    /// Encrypt data.
    ///
    /// Args:
    ///     data: Plaintext data (any length)
    ///
    /// Returns:
    ///     Ciphertext (same length as input)
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut cipher = TwofishCfbEnc::new_from_slices(&self.key, &self.iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let mut buffer = data.to_vec();
        cipher.encrypt(&mut buffer);
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Decrypt data.
    ///
    /// Args:
    ///     data: Ciphertext (any length)
    ///
    /// Returns:
    ///     Plaintext (same length as input)
    fn decrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut cipher = TwofishCfbDec::new_from_slices(&self.key, &self.iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let mut buffer = data.to_vec();
        cipher.decrypt(&mut buffer);
        Ok(PyBytes::new_bound(py, &buffer))
    }
}

impl Drop for TwofishCFB {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Twofish block cipher in OFB mode.
///
/// OFB (Output Feedback) mode turns a block cipher into a synchronous
/// stream cipher. It does not require padding.
#[pyclass]
struct TwofishOFB {
    key: Vec<u8>,
    iv: Vec<u8>,
}

#[pymethods]
impl TwofishOFB {
    /// Create a new TwofishOFB cipher.
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
        validate_iv_length(iv.len())?;
        Ok(Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
        })
    }

    /// Encrypt data.
    ///
    /// Args:
    ///     data: Plaintext data (any length)
    ///
    /// Returns:
    ///     Ciphertext (same length as input)
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        // Create Twofish cipher with variable key size, then wrap in OFB mode
        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let iv = cipher::generic_array::GenericArray::from_slice(&self.iv);
        let core = TwofishOfbCore::inner_iv_init(twofish, iv);
        let mut cipher = cipher::StreamCipherCoreWrapper::from_core(core);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        Ok(PyBytes::new_bound(py, &buffer))
    }

    /// Decrypt data.
    ///
    /// Args:
    ///     data: Ciphertext (any length)
    ///
    /// Returns:
    ///     Plaintext (same length as input)
    ///
    /// Note: In OFB mode, encryption and decryption are the same operation.
    fn decrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        // OFB mode: encryption and decryption are identical
        self.encrypt(py, data)
    }
}

impl Drop for TwofishOFB {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

// ============================================================================
// Helper functions
// ============================================================================

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

/// Validate IV/nonce length (16 bytes).
fn validate_iv_length(len: usize) -> PyResult<()> {
    if len != BLOCK_SIZE {
        return Err(PyValueError::new_err(format!(
            "IV/nonce must be {} bytes, got {}",
            BLOCK_SIZE, len
        )));
    }
    Ok(())
}

/// Apply padding to data based on the padding scheme.
fn apply_padding(data: &[u8], padding: Padding) -> PyResult<Vec<u8>> {
    match padding {
        Padding::NoPadding => {
            if data.len() % BLOCK_SIZE != 0 {
                return Err(PyValueError::new_err(format!(
                    "Data must be a multiple of {} bytes when using no padding, got {} bytes",
                    BLOCK_SIZE,
                    data.len()
                )));
            }
            Ok(data.to_vec())
        }
        Padding::Pkcs7 => {
            let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
            let mut padded = data.to_vec();
            padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
            Ok(padded)
        }
        Padding::Zeros => {
            let padding_len = if data.len() % BLOCK_SIZE == 0 {
                0
            } else {
                BLOCK_SIZE - (data.len() % BLOCK_SIZE)
            };
            let mut padded = data.to_vec();
            padded.extend(std::iter::repeat(0u8).take(padding_len));
            Ok(padded)
        }
        Padding::Iso7816 => {
            let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
            let mut padded = data.to_vec();
            padded.push(0x80);
            padded.extend(std::iter::repeat(0u8).take(padding_len - 1));
            Ok(padded)
        }
        Padding::AnsiX923 => {
            let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
            let mut padded = data.to_vec();
            padded.extend(std::iter::repeat(0u8).take(padding_len - 1));
            padded.push(padding_len as u8);
            Ok(padded)
        }
    }
}

/// Remove padding from data based on the padding scheme.
fn remove_padding(data: &[u8], padding: Padding) -> PyResult<&[u8]> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Cannot unpad empty data"));
    }

    match padding {
        Padding::NoPadding => Ok(data),
        Padding::Pkcs7 => {
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
        Padding::Zeros => {
            // Find last non-zero byte
            let mut end = data.len();
            while end > 0 && data[end - 1] == 0 {
                end -= 1;
            }
            Ok(&data[..end])
        }
        Padding::Iso7816 => {
            // Find 0x80 marker
            let mut end = data.len();
            while end > 0 && data[end - 1] == 0 {
                end -= 1;
            }
            if end == 0 || data[end - 1] != 0x80 {
                return Err(PyValueError::new_err("Invalid ISO 7816-4 padding"));
            }
            Ok(&data[..end - 1])
        }
        Padding::AnsiX923 => {
            let padding_len = data[data.len() - 1] as usize;
            if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > data.len() {
                return Err(PyValueError::new_err("Invalid ANSI X9.23 padding"));
            }
            // Validate padding bytes are zeros (except last)
            for &byte in &data[data.len() - padding_len..data.len() - 1] {
                if byte != 0 {
                    return Err(PyValueError::new_err("Invalid ANSI X9.23 padding"));
                }
            }
            Ok(&data[..data.len() - padding_len])
        }
    }
}

/// Block size constant (16 bytes / 128 bits)
#[pyfunction]
const fn block_size() -> usize {
    BLOCK_SIZE
}

/// Python module definition
#[pymodule]
fn _oxifish(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Padding>()?;
    m.add_class::<TwofishECB>()?;
    m.add_class::<TwofishCBC>()?;
    m.add_class::<TwofishCTR>()?;
    m.add_class::<TwofishCFB>()?;
    m.add_class::<TwofishOFB>()?;
    m.add_function(wrap_pyfunction!(block_size, m)?)?;
    m.add("BLOCK_SIZE", BLOCK_SIZE)?;
    Ok(())
}
