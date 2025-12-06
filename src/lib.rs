//! Python bindings for the RustCrypto Twofish block cipher.
//!
//! This crate provides Python bindings via PyO3 for the Twofish block cipher,
//! wrapping the RustCrypto `twofish` crate. It supports ECB, CBC, CTR, CFB, and OFB modes.

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use cipher::{AsyncStreamCipher, BlockDecrypt, BlockEncrypt, InnerIvInit};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use twofish::Twofish;
use zeroize::Zeroize;

const BLOCK_SIZE_BYTES: usize = 16;

// Type aliases for cipher modes
type TwofishCbcEnc = cbc::Encryptor<Twofish>;
type TwofishCbcDec = cbc::Decryptor<Twofish>;
type TwofishCtrCore = ctr::CtrCore<Twofish, ctr::flavors::Ctr128BE>;
type TwofishCtr = cipher::StreamCipherCoreWrapper<TwofishCtrCore>;
type TwofishCfbEnc = cfb_mode::Encryptor<Twofish>;
type TwofishCfbDec = cfb_mode::Decryptor<Twofish>;
type TwofishOfbCore = ofb::OfbCore<Twofish>;
type TwofishOfb = cipher::StreamCipherCoreWrapper<TwofishOfbCore>;

// ============================================================================
// Enums
// ============================================================================

/// Block size for Twofish (always 128 bits / 16 bytes).
/// IntEnum - can be used as integer in Python.
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockSize {
    /// 128-bit block size (16 bytes)
    #[pyo3(name = "BITS_128")]
    Bits128 = 16,
}

/// Key sizes supported by Twofish.
/// IntEnum - can be used as integer in Python.
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    /// 128-bit key (16 bytes)
    #[pyo3(name = "BITS_128")]
    Bits128 = 16,
    /// 192-bit key (24 bytes)
    #[pyo3(name = "BITS_192")]
    Bits192 = 24,
    /// 256-bit key (32 bytes)
    #[pyo3(name = "BITS_256")]
    Bits256 = 32,
}

impl KeySize {
    fn from_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(KeySize::Bits128),
            24 => Some(KeySize::Bits192),
            32 => Some(KeySize::Bits256),
            _ => None,
        }
    }
}

// PaddingStyle is now defined in Python as a StrEnum.
// Rust accepts string values directly.

// ============================================================================
// Standalone padding functions
// ============================================================================

/// Pad data to a multiple of block_size using the specified padding style.
///
/// Args:
///     data: Data to pad
///     block_size: Block size in bytes (must be 1-255)
///     style: Padding style (default: "pkcs7")
///
/// Returns:
///     Padded data
#[pyfunction]
#[pyo3(signature = (data, block_size=16, style="pkcs7"))]
fn pad<'py>(
    py: Python<'py>,
    data: &[u8],
    block_size: u8,
    style: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    if block_size == 0 {
        return Err(PyValueError::new_err("block_size must be at least 1"));
    }
    let bs = block_size as usize;

    let padded = match style {
        "pkcs7" => {
            let padding_len = bs - (data.len() % bs);
            let mut result = data.to_vec();
            result.extend(std::iter::repeat(padding_len as u8).take(padding_len));
            result
        }
        "zeros" => {
            let padding_len = if data.len() % bs == 0 {
                0
            } else {
                bs - (data.len() % bs)
            };
            let mut result = data.to_vec();
            result.extend(std::iter::repeat(0u8).take(padding_len));
            result
        }
        "iso7816" => {
            let padding_len = bs - (data.len() % bs);
            let mut result = data.to_vec();
            result.push(0x80);
            result.extend(std::iter::repeat(0u8).take(padding_len - 1));
            result
        }
        "ansix923" => {
            let padding_len = bs - (data.len() % bs);
            let mut result = data.to_vec();
            result.extend(std::iter::repeat(0u8).take(padding_len - 1));
            result.push(padding_len as u8);
            result
        }
        _ => {
            return Err(PyValueError::new_err(format!(
                "Unknown padding style: '{}'. Valid styles: pkcs7, zeros, iso7816, ansix923",
                style
            )));
        }
    };

    Ok(PyBytes::new(py, &padded))
}

/// Remove padding from data using the specified padding style.
///
/// Args:
///     data: Padded data
///     block_size: Block size in bytes (must be 1-255)
///     style: Padding style (default: "pkcs7")
///
/// Returns:
///     Unpadded data
///
/// Raises:
///     ValueError: If padding is invalid
#[pyfunction]
#[pyo3(signature = (data, block_size=16, style="pkcs7"))]
fn unpad<'py>(
    py: Python<'py>,
    data: &[u8],
    block_size: u8,
    style: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    if block_size == 0 {
        return Err(PyValueError::new_err("block_size must be at least 1"));
    }
    if data.is_empty() {
        return Err(PyValueError::new_err("Cannot unpad empty data"));
    }
    let bs = block_size as usize;

    let unpadded = match style {
        "pkcs7" => {
            let padding_len = data[data.len() - 1] as usize;
            if padding_len == 0 || padding_len > bs || padding_len > data.len() {
                return Err(PyValueError::new_err("Invalid PKCS7 padding"));
            }
            for &byte in &data[data.len() - padding_len..] {
                if byte as usize != padding_len {
                    return Err(PyValueError::new_err("Invalid PKCS7 padding"));
                }
            }
            &data[..data.len() - padding_len]
        }
        "zeros" => {
            let mut end = data.len();
            while end > 0 && data[end - 1] == 0 {
                end -= 1;
            }
            &data[..end]
        }
        "iso7816" => {
            let mut end = data.len();
            while end > 0 && data[end - 1] == 0 {
                end -= 1;
            }
            if end == 0 || data[end - 1] != 0x80 {
                return Err(PyValueError::new_err("Invalid ISO 7816-4 padding"));
            }
            &data[..end - 1]
        }
        "ansix923" => {
            let padding_len = data[data.len() - 1] as usize;
            if padding_len == 0 || padding_len > bs || padding_len > data.len() {
                return Err(PyValueError::new_err("Invalid ANSI X9.23 padding"));
            }
            for &byte in &data[data.len() - padding_len..data.len() - 1] {
                if byte != 0 {
                    return Err(PyValueError::new_err("Invalid ANSI X9.23 padding"));
                }
            }
            &data[..data.len() - padding_len]
        }
        _ => {
            return Err(PyValueError::new_err(format!(
                "Unknown padding style: '{}'. Valid styles: pkcs7, zeros, iso7816, ansix923",
                style
            )));
        }
    };

    Ok(PyBytes::new(py, unpadded))
}

// ============================================================================
// TwofishECB
// ============================================================================

/// Twofish block cipher in ECB mode.
///
/// ECB mode encrypts each block independently. This mode does NOT provide
/// semantic security and should only be used as a building block for other
/// modes or for compatibility with existing systems.
#[pyclass]
struct TwofishECB {
    key: Vec<u8>,
    cipher: Twofish,
}

#[pymethods]
impl TwofishECB {
    /// Create a new TwofishECB cipher.
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        let cipher = Twofish::new_from_slice(key)
            .map_err(|e| PyValueError::new_err(format!("Invalid key: {}", e)))?;
        Ok(Self {
            key: key.to_vec(),
            cipher,
        })
    }

    /// Block size in bytes (always 16).
    #[getter]
    fn block_size(&self) -> BlockSize {
        BlockSize::Bits128
    }

    /// Key size in bytes (16, 24, or 32).
    #[getter]
    fn key_size(&self) -> KeySize {
        KeySize::from_len(self.key.len()).unwrap()
    }

    /// Encrypt a single 16-byte block.
    fn encrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE_BYTES {
            return Err(PyValueError::new_err(format!(
                "Block must be {} bytes, got {}",
                BLOCK_SIZE_BYTES,
                block.len()
            )));
        }
        let mut output = [0u8; BLOCK_SIZE_BYTES];
        output.copy_from_slice(block);
        self.cipher.encrypt_block((&mut output).into());
        Ok(PyBytes::new(py, &output))
    }

    /// Decrypt a single 16-byte block.
    fn decrypt_block<'py>(&self, py: Python<'py>, block: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if block.len() != BLOCK_SIZE_BYTES {
            return Err(PyValueError::new_err(format!(
                "Block must be {} bytes, got {}",
                BLOCK_SIZE_BYTES,
                block.len()
            )));
        }
        let mut output = [0u8; BLOCK_SIZE_BYTES];
        output.copy_from_slice(block);
        self.cipher.decrypt_block((&mut output).into());
        Ok(PyBytes::new(py, &output))
    }
}

impl Drop for TwofishECB {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ============================================================================
// TwofishCBC and streaming encryptor/decryptor
// ============================================================================

/// Streaming CBC encryptor.
#[pyclass]
struct TwofishCBCEncryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
    buffer: Vec<u8>,
    finalized: bool,
}

#[pymethods]
impl TwofishCBCEncryptor {
    /// Process data and return ciphertext for complete blocks.
    /// Data must be block-aligned (multiple of 16 bytes).
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Encryptor already finalized"));
        }
        if data.len() % BLOCK_SIZE_BYTES != 0 {
            return Err(PyValueError::new_err(format!(
                "Data must be a multiple of {} bytes, got {}. Use pad() first.",
                BLOCK_SIZE_BYTES,
                data.len()
            )));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        // Determine the IV for this chunk (last block of previous output, or initial IV)
        let iv = if self.buffer.is_empty() {
            &self.iv
        } else {
            &self.buffer[self.buffer.len() - BLOCK_SIZE_BYTES..]
        };

        let encryptor = TwofishCbcEnc::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut output = data.to_vec();
        encryptor
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut output, data.len())
            .map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;

        // Store last block as next IV
        self.buffer = output[output.len() - BLOCK_SIZE_BYTES..].to_vec();

        Ok(PyBytes::new(py, &output))
    }

    /// Finalize the encryptor. Returns empty bytes.
    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Encryptor already finalized"));
        }
        self.finalized = true;
        Ok(PyBytes::new(py, &[]))
    }
}

impl Drop for TwofishCBCEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.buffer.zeroize();
    }
}

/// Streaming CBC decryptor.
#[pyclass]
struct TwofishCBCDecryptor {
    key: Vec<u8>,
    iv: Vec<u8>,
    last_block: Vec<u8>,
    finalized: bool,
}

#[pymethods]
impl TwofishCBCDecryptor {
    /// Process ciphertext and return plaintext for complete blocks.
    /// Data must be block-aligned (multiple of 16 bytes).
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Decryptor already finalized"));
        }
        if data.len() % BLOCK_SIZE_BYTES != 0 {
            return Err(PyValueError::new_err(format!(
                "Ciphertext must be a multiple of {} bytes, got {}",
                BLOCK_SIZE_BYTES,
                data.len()
            )));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let iv = if self.last_block.is_empty() {
            &self.iv
        } else {
            &self.last_block
        };

        let decryptor = TwofishCbcDec::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut output = data.to_vec();
        decryptor
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut output)
            .map_err(|e| PyRuntimeError::new_err(format!("Decryption failed: {}", e)))?;

        // Store last ciphertext block as next IV
        self.last_block = data[data.len() - BLOCK_SIZE_BYTES..].to_vec();

        Ok(PyBytes::new(py, &output))
    }

    /// Finalize the decryptor. Returns empty bytes.
    /// Use unpad() on the complete plaintext if padding was used.
    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Decryptor already finalized"));
        }
        self.finalized = true;
        Ok(PyBytes::new(py, &[]))
    }
}

impl Drop for TwofishCBCDecryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.last_block.zeroize();
    }
}

/// Twofish block cipher in CBC mode.
#[pyclass]
struct TwofishCBC {
    key: Vec<u8>,
}

#[pymethods]
impl TwofishCBC {
    /// Create a new TwofishCBC cipher.
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        Ok(Self { key: key.to_vec() })
    }

    #[getter]
    fn block_size(&self) -> BlockSize {
        BlockSize::Bits128
    }

    #[getter]
    fn key_size(&self) -> KeySize {
        KeySize::from_len(self.key.len()).unwrap()
    }

    /// Create a streaming encryptor with the given IV.
    fn encryptor(&self, iv: &[u8]) -> PyResult<TwofishCBCEncryptor> {
        validate_iv_length(iv.len())?;
        Ok(TwofishCBCEncryptor {
            key: self.key.clone(),
            iv: iv.to_vec(),
            buffer: Vec::new(),
            finalized: false,
        })
    }

    /// Create a streaming decryptor with the given IV.
    fn decryptor(&self, iv: &[u8]) -> PyResult<TwofishCBCDecryptor> {
        validate_iv_length(iv.len())?;
        Ok(TwofishCBCDecryptor {
            key: self.key.clone(),
            iv: iv.to_vec(),
            last_block: Vec::new(),
            finalized: false,
        })
    }

    /// Encrypt data (one-shot). Data must be block-aligned.
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        if data.len() % BLOCK_SIZE_BYTES != 0 {
            return Err(PyValueError::new_err(format!(
                "Data must be a multiple of {} bytes, got {}. Use pad() first.",
                BLOCK_SIZE_BYTES,
                data.len()
            )));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let encryptor = TwofishCbcEnc::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        encryptor
            .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, data.len())
            .map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;

        Ok(PyBytes::new(py, &buffer))
    }

    /// Decrypt data (one-shot). Use unpad() on result if padding was used.
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        if data.is_empty() || data.len() % BLOCK_SIZE_BYTES != 0 {
            return Err(PyValueError::new_err(format!(
                "Ciphertext must be non-empty and multiple of {} bytes, got {}",
                BLOCK_SIZE_BYTES,
                data.len()
            )));
        }

        let decryptor = TwofishCbcDec::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        decryptor
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
            .map_err(|e| PyRuntimeError::new_err(format!("Decryption failed: {}", e)))?;

        Ok(PyBytes::new(py, &buffer))
    }
}

impl Drop for TwofishCBC {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ============================================================================
// TwofishCTR and streaming
// ============================================================================

/// Streaming CTR encryptor/decryptor.
///
/// Stores the cipher state to provide O(1) streaming performance.
#[pyclass]
struct TwofishCTRCipher {
    cipher: Option<TwofishCtr>,
    finalized: bool,
}

#[pymethods]
impl TwofishCTRCipher {
    /// Process data (works for both encryption and decryption).
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Cipher already finalized"));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Cipher not initialized"))?;

        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }

    /// Finalize the cipher.
    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Cipher already finalized"));
        }
        self.finalized = true;
        // Drop the cipher to release resources
        self.cipher = None;
        Ok(PyBytes::new(py, &[]))
    }
}

// Note: TwofishCtr contains the key material internally and the underlying
// Twofish cipher implements ZeroizeOnDrop, so key material is securely cleared.

/// Twofish block cipher in CTR mode.
#[pyclass]
struct TwofishCTR {
    key: Vec<u8>,
}

#[pymethods]
impl TwofishCTR {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        Ok(Self { key: key.to_vec() })
    }

    #[getter]
    fn block_size(&self) -> BlockSize {
        BlockSize::Bits128
    }

    #[getter]
    fn key_size(&self) -> KeySize {
        KeySize::from_len(self.key.len()).unwrap()
    }

    /// Create a streaming cipher with the given nonce.
    fn encryptor(&self, nonce: &[u8]) -> PyResult<TwofishCTRCipher> {
        validate_iv_length(nonce.len())?;

        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let nonce_arr = cipher::generic_array::GenericArray::from_slice(nonce);
        let core = TwofishCtrCore::inner_iv_init(twofish, nonce_arr);
        let cipher = cipher::StreamCipherCoreWrapper::from_core(core);

        Ok(TwofishCTRCipher {
            cipher: Some(cipher),
            finalized: false,
        })
    }

    /// Create a streaming cipher (same as encryptor for CTR mode).
    fn decryptor(&self, nonce: &[u8]) -> PyResult<TwofishCTRCipher> {
        self.encryptor(nonce)
    }

    /// Encrypt data (one-shot).
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        nonce: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(nonce.len())?;
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let nonce_arr = cipher::generic_array::GenericArray::from_slice(nonce);
        let core = TwofishCtrCore::inner_iv_init(twofish, nonce_arr);
        let mut cipher = cipher::StreamCipherCoreWrapper::from_core(core);

        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }

    /// Decrypt data (one-shot).
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        nonce: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.encrypt(py, data, nonce)
    }
}

impl Drop for TwofishCTR {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ============================================================================
// TwofishCFB and streaming
// ============================================================================

/// Streaming CFB encryptor.
///
/// Note: CFB streaming requires block-aligned chunks (16 bytes) for correctness
/// when processing multiple chunks. Use one-shot encrypt() for arbitrary lengths.
#[pyclass]
struct TwofishCFBEncryptor {
    key: Vec<u8>,
    last_block: Vec<u8>,
    finalized: bool,
}

#[pymethods]
impl TwofishCFBEncryptor {
    /// Process data. For correct multi-chunk streaming, data must be block-aligned (16 bytes).
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Encryptor already finalized"));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let cipher = TwofishCfbEnc::new_from_slices(&self.key, &self.last_block)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        cipher.encrypt(&mut buffer);

        // Update feedback state with last ciphertext block
        if buffer.len() >= BLOCK_SIZE_BYTES {
            self.last_block = buffer[buffer.len() - BLOCK_SIZE_BYTES..].to_vec();
        }

        Ok(PyBytes::new(py, &buffer))
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Encryptor already finalized"));
        }
        self.finalized = true;
        Ok(PyBytes::new(py, &[]))
    }
}

impl Drop for TwofishCFBEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.last_block.zeroize();
    }
}

/// Streaming CFB decryptor.
///
/// Note: CFB streaming requires block-aligned chunks (16 bytes) for correctness
/// when processing multiple chunks. Use one-shot decrypt() for arbitrary lengths.
#[pyclass]
struct TwofishCFBDecryptor {
    key: Vec<u8>,
    last_block: Vec<u8>,
    finalized: bool,
}

#[pymethods]
impl TwofishCFBDecryptor {
    /// Process data. For correct multi-chunk streaming, data must be block-aligned (16 bytes).
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Decryptor already finalized"));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        // Save ciphertext for IV update before decryption
        let ct_for_iv = data.to_vec();

        let cipher = TwofishCfbDec::new_from_slices(&self.key, &self.last_block)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        cipher.decrypt(&mut buffer);

        // Update feedback state with last ciphertext block
        if ct_for_iv.len() >= BLOCK_SIZE_BYTES {
            self.last_block = ct_for_iv[ct_for_iv.len() - BLOCK_SIZE_BYTES..].to_vec();
        }

        Ok(PyBytes::new(py, &buffer))
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Decryptor already finalized"));
        }
        self.finalized = true;
        Ok(PyBytes::new(py, &[]))
    }
}

impl Drop for TwofishCFBDecryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.last_block.zeroize();
    }
}

/// Twofish block cipher in CFB mode.
#[pyclass]
struct TwofishCFB {
    key: Vec<u8>,
}

#[pymethods]
impl TwofishCFB {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        Ok(Self { key: key.to_vec() })
    }

    #[getter]
    fn block_size(&self) -> BlockSize {
        BlockSize::Bits128
    }

    #[getter]
    fn key_size(&self) -> KeySize {
        KeySize::from_len(self.key.len()).unwrap()
    }

    fn encryptor(&self, iv: &[u8]) -> PyResult<TwofishCFBEncryptor> {
        validate_iv_length(iv.len())?;
        Ok(TwofishCFBEncryptor {
            key: self.key.clone(),
            last_block: iv.to_vec(),
            finalized: false,
        })
    }

    fn decryptor(&self, iv: &[u8]) -> PyResult<TwofishCFBDecryptor> {
        validate_iv_length(iv.len())?;
        Ok(TwofishCFBDecryptor {
            key: self.key.clone(),
            last_block: iv.to_vec(),
            finalized: false,
        })
    }

    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let cipher = TwofishCfbEnc::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        cipher.encrypt(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }

    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let cipher = TwofishCfbDec::new_from_slices(&self.key, iv)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;

        let mut buffer = data.to_vec();
        cipher.decrypt(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }
}

impl Drop for TwofishCFB {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ============================================================================
// TwofishOFB and streaming
// ============================================================================

/// Streaming OFB cipher.
///
/// Stores the cipher state to provide O(1) streaming performance.
#[pyclass]
struct TwofishOFBCipher {
    cipher: Option<TwofishOfb>,
    finalized: bool,
}

#[pymethods]
impl TwofishOFBCipher {
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Cipher already finalized"));
        }
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let cipher = self
            .cipher
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Cipher not initialized"))?;

        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if self.finalized {
            return Err(PyRuntimeError::new_err("Cipher already finalized"));
        }
        self.finalized = true;
        // Drop the cipher to release resources
        self.cipher = None;
        Ok(PyBytes::new(py, &[]))
    }
}

// Note: TwofishOfb contains the key material internally and the underlying
// Twofish cipher implements ZeroizeOnDrop, so key material is securely cleared.

/// Twofish block cipher in OFB mode.
#[pyclass]
struct TwofishOFB {
    key: Vec<u8>,
}

#[pymethods]
impl TwofishOFB {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        Ok(Self { key: key.to_vec() })
    }

    #[getter]
    fn block_size(&self) -> BlockSize {
        BlockSize::Bits128
    }

    #[getter]
    fn key_size(&self) -> KeySize {
        KeySize::from_len(self.key.len()).unwrap()
    }

    fn encryptor(&self, iv: &[u8]) -> PyResult<TwofishOFBCipher> {
        validate_iv_length(iv.len())?;

        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let iv_arr = cipher::generic_array::GenericArray::from_slice(iv);
        let core = TwofishOfbCore::inner_iv_init(twofish, iv_arr);
        let cipher = cipher::StreamCipherCoreWrapper::from_core(core);

        Ok(TwofishOFBCipher {
            cipher: Some(cipher),
            finalized: false,
        })
    }

    fn decryptor(&self, iv: &[u8]) -> PyResult<TwofishOFBCipher> {
        self.encryptor(iv)
    }

    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        if data.is_empty() {
            return Ok(PyBytes::new(py, &[]));
        }

        let twofish = Twofish::new_from_slice(&self.key)
            .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))?;
        let iv_arr = cipher::generic_array::GenericArray::from_slice(iv);
        let core = TwofishOfbCore::inner_iv_init(twofish, iv_arr);
        let mut cipher = cipher::StreamCipherCoreWrapper::from_core(core);

        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);

        Ok(PyBytes::new(py, &buffer))
    }

    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        self.encrypt(py, data, iv)
    }
}

impl Drop for TwofishOFB {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn validate_key_length(len: usize) -> PyResult<()> {
    if len != 16 && len != 24 && len != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits), got {} bytes",
            len
        )));
    }
    Ok(())
}

fn validate_iv_length(len: usize) -> PyResult<()> {
    if len != BLOCK_SIZE_BYTES {
        return Err(PyValueError::new_err(format!(
            "IV/nonce must be {} bytes, got {}",
            BLOCK_SIZE_BYTES, len
        )));
    }
    Ok(())
}

// ============================================================================
// Module definition
// ============================================================================

#[pymodule]
fn _oxifish(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Enums (PaddingStyle is defined in Python as a StrEnum)
    m.add_class::<BlockSize>()?;
    m.add_class::<KeySize>()?;

    // Cipher classes
    m.add_class::<TwofishECB>()?;
    m.add_class::<TwofishCBC>()?;
    m.add_class::<TwofishCTR>()?;
    m.add_class::<TwofishCFB>()?;
    m.add_class::<TwofishOFB>()?;

    // Streaming encryptors/decryptors
    m.add_class::<TwofishCBCEncryptor>()?;
    m.add_class::<TwofishCBCDecryptor>()?;
    m.add_class::<TwofishCTRCipher>()?;
    m.add_class::<TwofishCFBEncryptor>()?;
    m.add_class::<TwofishCFBDecryptor>()?;
    m.add_class::<TwofishOFBCipher>()?;

    // Padding functions
    m.add_function(wrap_pyfunction!(pad, m)?)?;
    m.add_function(wrap_pyfunction!(unpad, m)?)?;

    // Constants (for backwards compatibility)
    m.add("BLOCK_SIZE", BLOCK_SIZE_BYTES)?;

    Ok(())
}
