//! `TwofishKey` (RFC 0001 new surface, slice 7) and its private
//! mode/padding/IV-parsing helpers.
//!
//! Split out of `lib.rs` in slice 17. Every helper below is used
//! exclusively from within `TwofishKey`'s own methods, so they stay
//! module-private rather than `pub(crate)`.

use std::sync::Arc;

use cipher::KeyInit;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use twofish::Twofish;

use crate::engine;
use crate::errors::engine_err_to_py;
use crate::session::{Direction, TwofishSession};
use crate::BLOCK_SIZE_BYTES;

/// New-surface key object (`_oxifish.TwofishKey`).
///
/// `#[pyclass(subclass)]`: the public, Python-facing `TwofishKey` in
/// `python/oxifish/__init__.py` subclasses this directly. Per the RFC's
/// module-boundary contract, Rust owns construction and the expanded key
/// schedule; the Python layer owns `Buffer` (bytes/bytearray/memoryview)
/// coercion, `Mode`/`Padding` string coercion, and wrapping results into
/// `EncryptResult`. Slice 8 added the private `_encrypt_raw`/`_decrypt_raw`
/// one-shot CBC-only methods; slice 10 (this revision) extends them with
/// `mode` dispatch over all four `Mode` values (cbc/ctr/cfb/ofb), each
/// routed through the matching `engine::Session` constructor. Streaming
/// session factories remain a later slice's deliverable (12) and this
/// class does not yet expose them.
///
/// Holds only the expanded `Arc<Twofish>` schedule -- raw key bytes are
/// copied zero *additional* times after construction (RFC: "Rust structure
/// (honest version)") -- plus the original key length, since `Twofish`'s
/// schedule doesn't itself recall it and `key_size` must stay readable.
/// The `Arc`'s reference-counted last-drop zeroizes the schedule via
/// `Twofish`'s own `zeroize`-feature `Drop` impl (see the
/// `twofish_key_schedule_drops_without_panic` test in `lib.rs`), so
/// `TwofishKey` needs no manual `Drop` impl of its own.
#[pyclass(subclass)]
pub(crate) struct TwofishKey {
    cipher: Arc<Twofish>,
    key_len: usize,
}

#[pymethods]
impl TwofishKey {
    /// Validate key length (16/24/32 bytes) and expand the schedule once.
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        validate_key_length(key.len())?;
        let cipher = new_cipher(key)?;
        Ok(Self {
            cipher: Arc::new(cipher),
            key_len: key.len(),
        })
    }

    /// Key size in bytes (16, 24, or 32).
    #[getter]
    fn key_size(&self) -> usize {
        self.key_len
    }

    /// Shows only `key_size` (in bits, matching the other cipher classes'
    /// `__repr__` convention) -- never key material (RFC Contracts:
    /// `__repr__`).
    fn __repr__(&self) -> String {
        format!("<TwofishKey key_size={}>", self.key_len * 8)
    }

    /// Private raw one-shot encrypt (RFC 0001 slice 8 "One-shot CBC hot
    /// path", extended by slice 10 "Remaining modes"). Constructs a fresh
    /// `engine::Session` -- from an independent clone of this key's
    /// schedule (RFC: "Rust structure (honest version)" -- no raw-key
    /// re-derivation) for CBC/CTR/CFB/OFB -- and drives it through the
    /// same `close_out` path streaming sessions use, per the Contracts'
    /// engine-unification requirement.
    ///
    /// `mode` and `padding` are the already-coerced-to-string (but not yet
    /// parsed) catalog values the Python facade computed from its
    /// `Mode | str` and `Padding | str | None` parameters; unrecognized
    /// `mode` values (including the literal string `"ecb"`, which has no
    /// carve-out beyond being absent from the valid set) raise the
    /// catalog's `ValueError` via [`parse_mode`], the single place mode
    /// strings are validated. `padding` is `None` when the Python facade's
    /// `padding` argument was omitted/`None`; per the Contracts' "Padding
    /// defaults & rejection" bullet, CBC treats that as PKCS7, while the
    /// three stream modes require it to stay `None` -- *any* explicit
    /// value (including `"none"`) is rejected by [`reject_stream_padding`].
    ///
    /// `iv=None` (RFC 0001 slice 13, "Auto-IV") auto-generates a fresh
    /// 16-byte IV via [`generate_iv`] (CSPRNG, the `getrandom` crate); an
    /// explicit `iv` is validated and used as-is. Always returns
    /// `(iv, ciphertext)` -- the Python facade decides, based on whether
    /// its own `iv` parameter was `None`, whether to wrap that pair into
    /// an `EncryptResult` or discard the (caller-already-owns-it) echoed
    /// IV and return bare `ciphertext` bytes (RFC Proposed Interface: the
    /// `@overload` pair on `TwofishKey.encrypt`). Every mode's `iv` is a
    /// full 16-byte block (CTR's is the initial counter block, per the
    /// RFC's CTR contract) -- the same length validation applies
    /// uniformly to the explicit case.
    ///
    /// **GIL release (RFC 0001 slice 15):** `data` is copied into an owned
    /// `Vec<u8>` while the GIL is still held (mirroring
    /// `TwofishSession::update`'s `PyBuffer::to_vec` discipline), *then*
    /// [`Python::detach`] releases the GIL around the pure-Rust
    /// `close_out` call -- never while holding a live borrow into
    /// caller-supplied memory (RFC Concurrency contract). `iv_owned` and
    /// `mode` are plain owned/`Copy` values, not borrows into Python
    /// memory, so they cross the closure freely.
    fn _encrypt_raw<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        mode: &str,
        iv: Option<&[u8]>,
        padding: Option<&str>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let iv_owned = resolve_iv(iv)?;
        let mode = parse_mode(mode)?;
        let mut session = self.new_session(Direction::Encrypt, mode, &iv_owned, padding)?;
        let owned_data = data.to_vec();
        let output = py
            .detach(|| session.close_out(&owned_data))
            .map_err(engine_err_to_py)?;
        Ok((PyBytes::new(py, &iv_owned), PyBytes::new(py, &output)))
    }

    /// Private raw one-shot decrypt. See [`TwofishKey::_encrypt_raw`] re:
    /// engine routing, mode/padding dispatch, and GIL release. Unlike
    /// `_encrypt_raw`, `iv` stays required (`&[u8]`, never `Option`): the
    /// RFC's auto-IV overload applies only to `encrypt`/`encryptor` --
    /// decrypting requires the IV the corresponding encryption used, which
    /// by definition cannot be generated here.
    ///
    /// Padded-decrypt failures (bad padding bytes, or padded ciphertext
    /// shorter than one block) surface as `DecryptionError` (RFC 0001
    /// slice 15, "Misuse machine + DecryptionError") via [`engine_err_to_py`]'s
    /// `DecryptionFailed` mapping; a `padding="none"` alignment mistake
    /// still surfaces as the catalog's plain `ValueError` (the
    /// `UnalignedLength` variant, mapped unchanged).
    fn _decrypt_raw<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        mode: &str,
        iv: &[u8],
        padding: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        validate_iv_length(iv.len())?;
        let mode = parse_mode(mode)?;
        let mut session = self.new_session(Direction::Decrypt, mode, &iv_array(iv), padding)?;
        let owned_data = data.to_vec();
        let output = py
            .detach(|| session.close_out(&owned_data))
            .map_err(engine_err_to_py)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Private raw streaming-encryptor factory (RFC 0001 slice 12,
    /// "Streaming plumbing + buffer protocol"). Mirrors
    /// [`TwofishKey::_encrypt_raw`]'s mode/padding dispatch -- both share
    /// [`TwofishKey::new_session`] (called with [`Direction::Encrypt`]), the
    /// single construction site for an encrypt-direction `engine::Session`
    /// -- but returns the session itself (`mode`/`direction`/`iv`
    /// populated) instead of driving it to completion via `close_out`. The
    /// `mode` string is echoed back via
    /// [`ModeSelector::as_str`] rather than the caller's original `mode`
    /// argument, so `TwofishSession.mode` always reports the canonical
    /// catalog spelling.
    ///
    /// `iv=None` auto-generates via [`generate_iv`] (RFC 0001 slice 13,
    /// "Auto-IV"), matching `_encrypt_raw`. The resulting `TwofishSession`
    /// exposes whichever IV was used (generated or caller-supplied)
    /// through its `.iv` getter -- readable both before and after
    /// `finalize()` (RFC Proposed Interface: "Readable after finalize()"),
    /// since that field lives independently of `engine::Session`'s
    /// Fresh/Streaming/Finalized state.
    fn _encryptor_raw(
        &self,
        mode: &str,
        iv: Option<&[u8]>,
        padding: Option<&str>,
    ) -> PyResult<TwofishSession> {
        let iv_owned = resolve_iv(iv)?;
        let mode = parse_mode(mode)?;
        let session = self.new_session(Direction::Encrypt, mode, &iv_owned, padding)?;
        Ok(TwofishSession {
            session,
            mode: mode.as_str(),
            direction: Direction::Encrypt,
            iv: Some(iv_owned.to_vec()),
        })
    }

    /// Private raw streaming-decryptor factory. See
    /// [`TwofishKey::_encryptor_raw`] re: mode/padding dispatch; calls
    /// [`TwofishKey::new_session`] with [`Direction::Decrypt`] instead.
    /// `iv` stays required (`&[u8]`) -- see [`TwofishKey::_decrypt_raw`]
    /// re: decrypt never getting an auto-IV overload.
    fn _decryptor_raw(
        &self,
        mode: &str,
        iv: &[u8],
        padding: Option<&str>,
    ) -> PyResult<TwofishSession> {
        validate_iv_length(iv.len())?;
        let mode = parse_mode(mode)?;
        let session = self.new_session(Direction::Decrypt, mode, &iv_array(iv), padding)?;
        Ok(TwofishSession {
            session,
            mode: mode.as_str(),
            direction: Direction::Decrypt,
            iv: Some(iv.to_vec()),
        })
    }

    /// Private raw ECB-encryptor factory (RFC 0001 slice 11, "ECB
    /// factories + KATs"). `padding` is the already-coerced-to-string
    /// catalog value the Python facade's `ecb_encryptor(*, padding: Padding
    /// | str)` computed -- mandatory (no `None` case), unlike the shared
    /// `encrypt`/`decrypt`'s optional `padding` (RFC Contracts: "ECB
    /// factories require explicit padding="). Constructs a fresh
    /// `engine::Session::ecb_encryptor`, borrowing this key's shared
    /// `Arc<Twofish>` schedule rather than cloning it (RFC: "ECB sessions
    /// borrow the key's schedule via `Arc<Twofish>`" -- the zeroization
    /// model non-ECB sessions don't share).
    fn _ecb_encryptor_raw(&self, padding: &str) -> PyResult<TwofishSession> {
        let padding = parse_padding(padding)?;
        Ok(TwofishSession {
            session: engine::Session::ecb_encryptor(Arc::clone(&self.cipher), padding),
            mode: ECB_MODE_STR,
            direction: Direction::Encrypt,
            iv: None,
        })
    }

    /// Private raw ECB-decryptor factory. See
    /// [`TwofishKey::_ecb_encryptor_raw`] re: mandatory `padding` and the
    /// shared-schedule borrow.
    fn _ecb_decryptor_raw(&self, padding: &str) -> PyResult<TwofishSession> {
        let padding = parse_padding(padding)?;
        Ok(TwofishSession {
            session: engine::Session::ecb_decryptor(Arc::clone(&self.cipher), padding),
            mode: ECB_MODE_STR,
            direction: Direction::Decrypt,
            iv: None,
        })
    }
}

impl TwofishKey {
    /// Build a fresh `engine::Session` for the given direction and mode,
    /// dispatching each `ModeSelector` variant onto the matching pair of
    /// `engine::Session` constructors (F12: unifies what were previously
    /// two near-duplicate `new_encrypt_session`/`new_decrypt_session`
    /// methods, differing only in which constructor of each pair they
    /// called -- now a single `direction` match nested inside each mode
    /// arm). CBC parses `padding` (defaulting the `None` case to PKCS7,
    /// the RFC's stated CBC default); the three stream modes reject any
    /// explicit `padding` via [`reject_stream_padding`] and otherwise
    /// carry none.
    fn new_session(
        &self,
        direction: Direction,
        mode: ModeSelector,
        iv: &[u8; BLOCK_SIZE_BYTES],
        padding: Option<&str>,
    ) -> PyResult<engine::Session> {
        Ok(match mode {
            ModeSelector::Cbc => {
                let padding = parse_padding(padding.unwrap_or("pkcs7"))?;
                let cipher = (*self.cipher).clone();
                match direction {
                    Direction::Encrypt => engine::Session::cbc_encryptor(cipher, iv, padding),
                    Direction::Decrypt => engine::Session::cbc_decryptor(cipher, iv, padding),
                }
            }
            ModeSelector::Ctr => {
                reject_stream_padding(mode, padding)?;
                let cipher = (*self.cipher).clone();
                match direction {
                    Direction::Encrypt => engine::Session::ctr_encryptor(cipher, iv),
                    Direction::Decrypt => engine::Session::ctr_decryptor(cipher, iv),
                }
            }
            ModeSelector::Cfb => {
                reject_stream_padding(mode, padding)?;
                let cipher = (*self.cipher).clone();
                match direction {
                    Direction::Encrypt => engine::Session::cfb_encryptor(cipher, iv),
                    Direction::Decrypt => engine::Session::cfb_decryptor(cipher, iv),
                }
            }
            ModeSelector::Ofb => {
                reject_stream_padding(mode, padding)?;
                let cipher = (*self.cipher).clone();
                match direction {
                    Direction::Encrypt => engine::Session::ofb_encryptor(cipher, iv),
                    Direction::Decrypt => engine::Session::ofb_decryptor(cipher, iv),
                }
            }
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

#[inline]
fn validate_key_length(len: usize) -> PyResult<()> {
    if len != 16 && len != 24 && len != 32 {
        return Err(PyValueError::new_err(format!(
            "Key must be 16, 24, or 32 bytes (128, 192, or 256 bits), got {} bytes",
            len
        )));
    }
    Ok(())
}

/// IV-length validation for `TwofishKey`/`TwofishSession`'s raw methods.
/// Every IV mode (CBC/CTR/CFB/OFB) takes a full 16-byte block -- for CTR
/// this is the initial counter block (`Ctr128BE`), not a nonce+counter
/// split (RFC Contracts: "CTR `iv`").
#[inline]
fn validate_iv_length(len: usize) -> PyResult<()> {
    if len != BLOCK_SIZE_BYTES {
        return Err(PyValueError::new_err(format!(
            "IV must be {} bytes, got {}",
            BLOCK_SIZE_BYTES, len
        )));
    }
    Ok(())
}

/// Generate a fresh 16-byte IV via the OS CSPRNG (RFC 0001 slice 13,
/// "Auto-IV"; RFC Dependency Strategy's named `getrandom` boundary). The
/// sole call site for `getrandom::fill` -- both one-shot auto-IV
/// (`_encrypt_raw`) and session auto-IV (`_encryptor_raw`) go through
/// [`resolve_iv`] below, which is this function's only caller, so
/// `getrandom` never appears anywhere else in the crate.
///
/// `getrandom::fill` failing at all is exceptionally rare (it means the
/// platform's CSPRNG source itself is unavailable) -- surfaced as
/// `RuntimeError` rather than `ValueError` since it is not a caller
/// usage mistake.
#[inline]
fn generate_iv() -> PyResult<[u8; BLOCK_SIZE_BYTES]> {
    let mut iv = [0u8; BLOCK_SIZE_BYTES];
    getrandom::fill(&mut iv)
        .map_err(|e| PyRuntimeError::new_err(format!("failed to generate random IV: {e}")))?;
    Ok(iv)
}

/// Resolve the new surface's `iv: Option<&[u8]>` raw-method parameter:
/// `None` (the Python facade's `iv=None`) auto-generates via
/// [`generate_iv`]; `Some(iv)` is length-validated and copied as-is. The
/// shared entry point `TwofishKey::_encrypt_raw`/`TwofishKey::_encryptor_raw`
/// both call, so auto-IV generation has exactly one implementation
/// regardless of which surface (one-shot vs. streaming) triggered it.
#[inline]
fn resolve_iv(iv: Option<&[u8]>) -> PyResult<[u8; BLOCK_SIZE_BYTES]> {
    match iv {
        Some(iv) => {
            validate_iv_length(iv.len())?;
            Ok(iv_array(iv))
        }
        None => generate_iv(),
    }
}

/// `TwofishSession.mode`'s catalog string for ECB sessions -- the two
/// `_ecb_*_raw` factories share this single literal instead of each
/// hand-writing `"ecb"` (F4), since [`ModeSelector`] deliberately has no
/// `Ecb` variant for those two sites to draw on (see its own docs).
const ECB_MODE_STR: &str = "ecb";

/// The new (RFC 0001) surface's shared-factory mode selector -- the
/// Rust-side counterpart of the Python facade's `Mode` `StrEnum`, plus
/// nothing else: ECB is reachable only via the (later-slice) `ecb_*`
/// factories, never through this type, so it has no `Ecb` variant. Parsed
/// from a catalog string exactly once, in [`parse_mode`] below (RFC
/// slice 10: "Mode-string validation in ONE place").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModeSelector {
    Cbc,
    Ctr,
    Cfb,
    Ofb,
}

impl ModeSelector {
    /// The single catalog table for this type (RFC 0002 change 3): each
    /// `(variant, catalog string)` pair appears exactly once, in the order
    /// the `"expected one of '…'"` message lists them. [`ModeSelector::as_str`]
    /// and [`parse_mode`] both derive from this table -- the match arms,
    /// the valid set, and the error message text can no longer drift
    /// independently because they are no longer three separate things.
    const ALL: [(ModeSelector, &'static str); 4] = [
        (ModeSelector::Cbc, "cbc"),
        (ModeSelector::Ctr, "ctr"),
        (ModeSelector::Cfb, "cfb"),
        (ModeSelector::Ofb, "ofb"),
    ];

    /// The catalog string for this mode -- used to echo the mode back in
    /// [`reject_stream_padding`]'s error message.
    fn as_str(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(variant, _)| *variant == self)
            .map(|(_, s)| *s)
            .expect("every ModeSelector variant has an entry in ALL")
    }
}

/// Parse a catalog string against a `(variant, string)` table, producing
/// either the matching variant or a `ValueError` naming the received value
/// and the full valid set -- joined from the same table, in table order, so
/// the message can never list a different set than the table actually
/// accepts (RFC 0002 change 3). Shared by [`parse_mode`] and
/// [`parse_padding`].
#[inline]
fn parse_catalog<T: Copy>(table: &[(T, &str)], kind: &str, value: &str) -> PyResult<T> {
    table
        .iter()
        .find(|(_, s)| *s == value)
        .map(|(variant, _)| *variant)
        .ok_or_else(|| {
            let valid = table
                .iter()
                .map(|(_, s)| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ");
            PyValueError::new_err(format!("invalid {kind} '{value}': expected one of {valid}"))
        })
}

/// Parse a `Mode` catalog string (already coerced from the Python facade's
/// `Mode | str` parameter) into [`ModeSelector`]. The single place mode
/// strings are validated (RFC slice 10 bullet), shared by `_encrypt_raw`
/// and `_decrypt_raw`. Exact, case-sensitive match, no trimming or
/// normalization (RFC Contracts: "Mode/Padding strings match exactly").
///
/// The literal string `"ecb"` is rejected here exactly like any other
/// unrecognized value -- it gets no special carve-out beyond simply being
/// absent from [`ModeSelector::ALL`], per the RFC's explicit callout that
/// `"ecb"` "is rejected... exactly like any unknown mode."
#[inline]
fn parse_mode(mode: &str) -> PyResult<ModeSelector> {
    parse_catalog(&ModeSelector::ALL, "mode", mode)
}

/// Reject an explicit `padding` argument on a stream mode (CTR/CFB/OFB).
/// Per the RFC Contracts' "Padding defaults & rejection" bullet: stream
/// modes raise `ValueError` on *any* explicit `padding=` value -- including
/// the string `"none"` -- while an omitted (`None`) `padding` is fine (no
/// padding is ever applied to a stream mode). This is not a catalogued
/// error-table entry (the RFC's Error catalog is silent on its exact
/// wording), so the message here is Corey-tunable; regression-tested at
/// the Python boundary.
#[inline]
fn reject_stream_padding(mode: ModeSelector, padding: Option<&str>) -> PyResult<()> {
    match padding {
        None => Ok(()),
        Some(_) => Err(PyValueError::new_err(format!(
            "padding is not supported for mode '{}': stream modes (ctr, cfb, ofb) must omit \
             the padding argument",
            mode.as_str()
        ))),
    }
}

/// The single catalog table for `engine::Padding` (RFC 0002 change 3), in
/// the order the `"expected one of '…'"` message lists them. [`parse_padding`]
/// is the table's only reader -- unlike [`ModeSelector`], nothing else in
/// this crate needs a variant-to-string mapping for padding, so the table
/// lives here rather than as an `impl` item on `engine::Padding`.
const PADDING_TABLE: [(engine::Padding, &str); 5] = [
    (engine::Padding::Pkcs7, "pkcs7"),
    (engine::Padding::None, "none"),
    (engine::Padding::Iso7816, "iso7816"),
    (engine::Padding::AnsiX923, "ansix923"),
    (engine::Padding::Zeros, "zeros"),
];

/// Parse a `Padding` catalog string (already coerced from the Python
/// facade's `Padding | str | None` parameter) into the engine's enum.
/// Exact, case-sensitive match, no trimming or normalization (RFC
/// Contracts: "Mode/Padding strings match exactly"); an unrecognized
/// value raises the catalog's `ValueError`, naming the received value and
/// the full valid set -- joined from [`PADDING_TABLE`], so it can never
/// list a different set than the table actually accepts.
#[inline]
fn parse_padding(padding: &str) -> PyResult<engine::Padding> {
    parse_catalog(&PADDING_TABLE, "padding", padding)
}

/// Expand a raw key into a fresh `Twofish` schedule for one engine session.
/// Every non-ECB session owns its own independent clone (see engine module
/// docs), so this is called once per `encryptor()`/`decryptor()`/one-shot
/// call -- never per `update()`, unlike the pre-engine CBC/CFB
/// implementations this replaces.
#[inline]
fn new_cipher(key: &[u8]) -> PyResult<Twofish> {
    Twofish::new_from_slice(key)
        .map_err(|e| PyRuntimeError::new_err(format!("Cipher init failed: {}", e)))
}

/// Convert an already-length-validated IV/nonce slice into the fixed-size
/// array the engine's session constructors take.
#[inline]
fn iv_array(iv: &[u8]) -> [u8; BLOCK_SIZE_BYTES] {
    iv.try_into()
        .expect("validate_iv_length already checked the length")
}

#[cfg(test)]
mod tests {
    use super::TwofishKey;

    #[test]
    fn twofish_key_accepts_every_valid_key_length() {
        for len in [16usize, 24, 32] {
            let key = vec![0x11u8; len];
            let k = TwofishKey::new(&key).expect("valid key length");
            assert_eq!(k.key_size(), len);
        }
    }

    // NB: `TwofishKey::new`'s invalid-length *error* path (unlike the
    // success path exercised above) constructs a `PyValueError`, which
    // panics outside an attached Python interpreter -- `cargo test` here
    // deliberately doesn't link/initialize one (see `lib.rs`'s
    // module-level zeroization comment re: `extension-module`), matching
    // this crate's existing convention that PyO3-boundary error paths are
    // covered by pytest, not `cargo test` (see engine.rs's tests, which
    // stick entirely to the pure-Rust `engine::Session`/`EngineError`
    // types for exactly this reason). The exact message is regression
    // tested at the Python boundary in
    // tests/test_key.py::TestTwofishKeyConstruction::test_rejects_every_invalid_key_length.

    #[test]
    fn twofish_key_repr_shows_key_size_in_bits_never_key_material() {
        let key = [0xABu8; 32];
        let k = TwofishKey::new(&key).expect("32-byte key is valid");
        let repr = k.__repr__();
        assert_eq!(repr, "<TwofishKey key_size=256>");
        // The repr must never leak key material -- confirm the raw key's
        // hex representation doesn't appear in it.
        assert!(!repr.contains("ab"), "repr leaked key bytes: {repr}");
        assert!(!repr.contains("AB"), "repr leaked key bytes: {repr}");
    }
}
