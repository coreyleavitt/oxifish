//! `TwofishXTS` PyO3 surface (RFC 0003 slice 4, "XTS Python surface").
//!
//! Mirrors `key.rs`'s `TwofishKey` two-layer pattern exactly (per the RFC's
//! Proposed Interface §2, "Implementation pattern pinned"): this
//! `#[pyclass(subclass)]` owns construction and the two expanded `Twofish`
//! schedules the in-repo [`crate::xts::XtsCipher`] engine (slice 3) needs;
//! the public, Python-facing `TwofishXTS` in `python/oxifish/__init__.py`
//! subclasses it directly and owns `Buffer` coercion, the single-
//! concatenated-key split, the equal-halves guard, and `tweak` range
//! validation. Per the RFC's §2 scoping note, the equal-halves check is a
//! facade-only guard -- this constructor takes two already-split,
//! already-length-implied-valid key halves and must accept them even if
//! equal (the official IEEE 1619 Vector 1 uses Key1 == Key2; `src/xts.rs`'s
//! own cargo tests already prove the engine accepts that case).
//!
//! **GIL contract (RFC 0003 §2, restated per-class, not inherited by
//! implication):** `_encrypt_raw`/`_decrypt_raw` copy the input buffer to
//! owned memory while the GIL is held (mirroring `TwofishKey::_encrypt_raw`'s
//! `data.to_vec()` and `TwofishSession::update`'s `PyBuffer::to_vec`
//! discipline), then release the GIL via [`Python::detach`] around the pure
//! `XtsCipher::encrypt_data_unit`/`decrypt_data_unit` transform only -- never
//! while holding a live borrow into caller-supplied memory.
//!
//! **Check-before-copy (code-review finding L1):** both methods call
//! [`xts::validate_len`] on the *borrowed* `data` slice's length before
//! `data.to_vec()` runs, so an oversized input is rejected without ever
//! paying for the full-input copy. `XtsCipher::encrypt_data_unit`/
//! `decrypt_data_unit` still re-check the same bound internally (defense in
//! depth, see that module's docs) -- this boundary check is an optimization
//! that skips a wasted allocation, not a replacement for the engine's own
//! guarantee that it never touches an out-of-range length.
//!
//! **Zeroization (RFC 0003 §2, "matches RFC 0001 in full"):** the two
//! expanded key schedules zeroize on this struct's drop via
//! [`crate::xts::XtsCipher`]'s `ZeroizeOnDrop` forwarding impl (no custom
//! `Drop` needed here, same reasoning as that impl's own doc comment).
//! Beyond the key schedules, the *owned copies of input/output data* made
//! at this boundary -- the GIL-soundness copy of the caller's buffer, and
//! the `Vec<u8>` the engine returns before it is copied into a Python
//! `bytes` object -- are zeroized explicitly after use, matching the
//! treatment RFC 0001 gives `engine::Session`'s `Pending`/`HeldBlock`
//! plaintext. (Any ciphertext-stealing scratch is already zeroized inside
//! `XtsCipher` itself -- see that module's docs.)
//!
//! Error mapping: [`XtsError::InvalidLength`] maps to `ValueError` with its
//! own `Display` string, which already matches the RFC's cataloged
//! `"XTS data unit must be {min} to {max} bytes, got {n} bytes"` wording
//! verbatim (see `src/xts.rs`) -- no reformatting needed here. Both the
//! check-before-copy call above and `XtsCipher`'s own internal check go
//! through this same [`xts_err_to_py`] mapping, so the raised `ValueError`
//! string is byte-identical regardless of which of the two call sites
//! catches the bad length.

use cipher::KeyInit;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use twofish::Twofish;
use zeroize::Zeroize;

use crate::xts::{self, XtsCipher, XtsError};

/// Base pyclass for the XTS surface (`_oxifish.TwofishXTS`). See the module
/// docs re: the two-layer split with `oxifish.TwofishXTS`
/// (`python/oxifish/__init__.py`).
#[pyclass(subclass)]
pub(crate) struct TwofishXTS {
    xts: XtsCipher<Twofish>,
    /// Total key length in bytes (32/48/64) -- `key1.len() + key2.len()`,
    /// matching `TwofishKey::key_len`'s "readable without re-deriving from
    /// the schedule" role. Per the RFC's §2 ergonomics note, `key_size`
    /// reports the *total*, not the per-half length.
    key_len: usize,
}

#[pymethods]
impl TwofishXTS {
    /// Build from two already-split key halves (the Python facade computed
    /// them from one concatenated `Buffer` and already rejected any length
    /// outside {32, 48, 64} total / validated the halves are unequal --
    /// see the module docs re: scoping). Each half independently expands to
    /// a `Twofish` schedule via [`Twofish::new_from_slice`], which itself
    /// only accepts 16/24/32-byte keys -- since the facade always splits an
    /// even {32,48,64}-byte buffer exactly in half, both halves are always
    /// one of those three lengths together.
    #[new]
    fn new(key1: &[u8], key2: &[u8]) -> PyResult<Self> {
        let data_cipher = new_cipher(key1)?;
        let tweak_cipher = new_cipher(key2)?;
        Ok(Self {
            xts: XtsCipher::new(data_cipher, tweak_cipher),
            key_len: key1.len() + key2.len(),
        })
    }

    /// Total key size in bytes (32, 48, or 64) -- see the struct-level
    /// `key_len` doc re: "total, not per-half".
    #[getter]
    fn key_size(&self) -> usize {
        self.key_len
    }

    /// Shows only `key_size` (in bytes, matching this class's `key_size`
    /// meaning -- unlike `TwofishKey::__repr__`, which reports bits) --
    /// never key material (RFC Contracts: `__repr__`; RFC §2's literal
    /// example format: `<TwofishXTS key_size=64>`). Angle-bracket style
    /// (code-review finding L4) unifies with `TwofishKey::__repr__`'s
    /// `<TwofishKey key_size=256>` -- only the bracket style changed here,
    /// not the bytes-vs-bits unit choice, which stays deliberately
    /// different per the RFC §2 note above.
    fn __repr__(&self) -> String {
        format!("<TwofishXTS key_size={}>", self.key_len)
    }

    /// Private raw one-shot encrypt. `data` is one IEEE 1619 data unit;
    /// `tweak` is its already-range-validated (by the Python facade, per
    /// the RFC's "never OverflowError" requirement) data-unit number,
    /// little-endian encoded into the 128-bit tweak block by
    /// [`XtsCipher::encrypt_data_unit`] itself (tweak-block encoding lives
    /// in the engine, not this facade -- see `src/xts.rs`'s module docs).
    ///
    /// See the module docs re: the GIL-release and zeroization contracts,
    /// both exercised here.
    fn _encrypt_raw<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        tweak: u128,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // Check-before-copy (module docs, code-review finding L1): reject
        // an out-of-range length on the borrowed slice before paying for
        // `to_vec()`'s full-input copy.
        xts::validate_len(data.len()).map_err(xts_err_to_py)?;
        let mut owned = data.to_vec();
        let result = py.detach(|| self.xts.encrypt_data_unit(&owned, tweak));
        owned.zeroize();
        let mut output = result.map_err(xts_err_to_py)?;
        let bytes = PyBytes::new(py, &output);
        output.zeroize();
        Ok(bytes)
    }

    /// Private raw one-shot decrypt. See [`TwofishXTS::_encrypt_raw`] re:
    /// tweak encoding, GIL release, and zeroization -- all identical here,
    /// mirrored for the decrypt direction.
    fn _decrypt_raw<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        tweak: u128,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // Check-before-copy: see `_encrypt_raw`'s identical comment.
        xts::validate_len(data.len()).map_err(xts_err_to_py)?;
        let mut owned = data.to_vec();
        let result = py.detach(|| self.xts.decrypt_data_unit(&owned, tweak));
        owned.zeroize();
        let mut output = result.map_err(xts_err_to_py)?;
        let bytes = PyBytes::new(py, &output);
        output.zeroize();
        Ok(bytes)
    }
}

/// Expand one key half into a fresh `Twofish` schedule. Mirrors
/// `key.rs::new_cipher` exactly (not shared -- that helper is module-private
/// to `key.rs`, and duplicating four lines here avoids making it
/// crate-public for a single extra call site).
#[inline]
fn new_cipher(key: &[u8]) -> PyResult<Twofish> {
    Twofish::new_from_slice(key)
        .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))
}

/// Map an [`XtsError`] onto the RFC's cataloged `ValueError` -- the engine's
/// `Display` impl already renders the exact cataloged string (see
/// `src/xts.rs`), so this is a bare wrap, not a reformat.
#[inline]
fn xts_err_to_py(err: XtsError) -> PyErr {
    PyValueError::new_err(err.to_string())
}
