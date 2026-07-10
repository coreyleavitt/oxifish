//! `TwofishSession` (RFC 0001 new surface, slice 11).
//!
//! Split out of `lib.rs` in slice 17.

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::engine;
use crate::errors::session_err_to_py;

/// A session's direction: the typed counterpart of
/// `TwofishSession.direction`'s catalog string ("encrypt"/"decrypt"),
/// mirroring `ModeSelector`'s (in `key.rs`) own `as_str()` pattern. Every
/// `TwofishSession { direction, .. }` construction site (four of them, in
/// `_encryptor_raw`/`_decryptor_raw`/`_ecb_encryptor_raw`/`_ecb_decryptor_raw`)
/// states its direction as one of these two variants rather than a
/// hand-written string literal, so a copy-paste slip (writing
/// `direction: "encrypt"` in a decrypt factory) fails to compile instead of
/// silently mislabeling the session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

impl Direction {
    /// The catalog string for this direction -- `TwofishSession.direction`'s
    /// exact observable value.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Direction::Encrypt => "encrypt",
            Direction::Decrypt => "decrypt",
        }
    }
}

/// Streaming session object, obtained via `TwofishKey`'s factory methods.
/// Per the RFC's module-boundary contract, this class is returned directly
/// from Rust -- unlike `TwofishKey`, there is no Python subclass wrapping
/// it.
///
/// **Construction:** `TwofishKey::_ecb_encryptor_raw`/`_ecb_decryptor_raw`
/// (slice 11) construct `mode == "ecb"` sessions with `iv == None`
/// (accessing `.iv` raises `AttributeError`); `TwofishKey::_encryptor_raw`
/// (slice 12, extended by slice 13's auto-IV) constructs `mode in {"cbc",
/// "ctr", "cfb", "ofb"}` encrypt sessions with `iv` either caller-supplied
/// or freshly generated via `generate_iv` when the caller omits it;
/// `_decryptor_raw` always takes an explicit `iv` (decrypt has no auto-IV
/// overload -- see `TwofishKey::_decrypt_raw`). All construction happens
/// in `key.rs`, which is why this struct's fields are `pub(crate)`.
///
/// **`update`/`finalize` accept the buffer protocol** (bytes/bytearray/
/// memoryview, since slice 12), via [`pyo3::buffer::PyBuffer`]: the input
/// is copied into an owned `Vec<u8>` (`PyBuffer::to_vec`) while the GIL is
/// held, satisfying the RFC's Concurrency contract -- "buffer-protocol
/// input is copied into engine-owned memory while the GIL is held". As of
/// slice 15, [`Python::detach`] then releases the GIL around the
/// pure-Rust `ingest`/`close_out` call itself, over that owned copy only
/// -- see each method's own doc for the release site. `TwofishKey::_encrypt_raw`
/// et al. still take plain `&[u8]` (`bytes`-only, per PyO3 0.27's
/// `FromPyObject` impl for `&[u8]`), since those have a Python-facing
/// wrapper (`TwofishKey.encrypt`/`decrypt`) that already coerces the wider
/// `Buffer` union to `bytes` before crossing into Rust -- `TwofishSession`
/// has no such wrapper, so its own `Buffer` acceptance lives at the Rust
/// boundary instead.
#[pyclass]
pub(crate) struct TwofishSession {
    pub(crate) session: engine::Session,
    /// `"cbc" | "ctr" | "cfb" | "ofb" | "ecb"`.
    pub(crate) mode: &'static str,
    /// Typed direction (F4); [`Direction::as_str`] gives the observable
    /// `"encrypt"` / `"decrypt"` catalog string.
    pub(crate) direction: Direction,
    /// `None` for ECB sessions (no IV concept -- `.iv` raises
    /// `AttributeError`); populated for the other four modes, either
    /// caller-supplied or auto-generated (encrypt sessions only). Stays
    /// readable after `finalize()` -- this field is independent of
    /// `engine::Session`'s Fresh/Streaming/Finalized state.
    pub(crate) iv: Option<Vec<u8>>,
}

#[pymethods]
impl TwofishSession {
    /// See the struct-level `mode` field doc.
    #[getter]
    fn mode(&self) -> &str {
        self.mode
    }

    /// See the struct-level `direction` field doc.
    #[getter]
    fn direction(&self) -> &str {
        self.direction.as_str()
    }

    /// The IV in use; unconditionally `bytes` for the four IV modes
    /// (slices 12-13). ECB sessions have no IV -- accessing this raises
    /// `AttributeError` at runtime (RFC Proposed Interface: "on ECB
    /// sessions access raises AttributeError at runtime"). The descriptor
    /// stays visible in `dir()`/stubs regardless -- a PyO3 limitation the
    /// RFC explicitly accepts rather than growing a second session type.
    #[getter]
    fn iv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        match &self.iv {
            Some(iv) => Ok(PyBytes::new(py, iv)),
            None => Err(PyAttributeError::new_err(
                "'TwofishSession' object has no attribute 'iv' (ECB sessions have no IV)",
            )),
        }
    }

    /// Ingest one chunk; any length, alignment handled by the engine's
    /// internal buffering. `RuntimeError` after `finalize()` (catalog:
    /// "session is already finalized").
    ///
    /// `data` accepts any buffer-protocol object (`bytes`/`bytearray`/
    /// `memoryview`) via [`pyo3::buffer::PyBuffer`]; [`PyBuffer::to_vec`]
    /// copies it into an owned `Vec<u8>` before this method touches the
    /// engine, and that copy happens while the GIL is held -- so a
    /// `bytearray` mutated by another thread, even *while* this call is in
    /// flight, cannot affect the bytes already copied (RFC Concurrency
    /// contract: "copied into engine-owned memory while the GIL is held").
    ///
    /// **GIL release (RFC 0001 slice 15):** once the copy above completes,
    /// [`Python::detach`] releases the GIL around the pure-Rust
    /// `ingest` call -- the only thing borrowed across that release is
    /// `&mut self.session` (engine-owned, `Send`) and `&owned` (the fresh
    /// copy just made), never a live borrow into caller-supplied memory.
    /// This is also what makes two threads racing `update`/`finalize` on
    /// the *same* session observable as PyO3's `PyBorrowMutError` ->
    /// `RuntimeError("Already borrowed")` (catalog: "Concurrent access to
    /// one session") -- without a real GIL-release window, a second
    /// thread could never get scheduled in time to attempt the second
    /// borrow.
    fn update<'py>(
        &mut self,
        py: Python<'py>,
        data: PyBuffer<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let owned = data.to_vec(py)?;
        let session = &mut self.session;
        let output = py
            .detach(|| session.ingest(&owned))
            .map_err(session_err_to_py)?;
        Ok(PyBytes::new(py, &output))
    }

    /// Optional final chunk + flush + apply/verify padding; consumes the
    /// session (`update`/`finalize` barred afterwards; properties stay
    /// readable). `data` defaults to `b""` (via `None`, since
    /// [`pyo3::buffer::PyBuffer`] has no zero-argument constructor to use
    /// as a `#[pyo3(signature)]` default) and is load-bearing: it keeps
    /// ECB one-shot use a single expression --
    /// `key.ecb_encryptor(padding=...).finalize(block)` -- since ECB has
    /// no dedicated one-shot method (RFC Proposed Interface).
    ///
    /// See [`TwofishSession::update`] re: buffer-protocol acceptance, the
    /// copy-while-GIL-held soundness invariant, and GIL release, all of
    /// which apply identically here. Padded-decrypt failures (bad padding
    /// bytes, or padded ciphertext shorter than one block) surface as
    /// `DecryptionError` via [`session_err_to_py`]'s delegation to
    /// `engine_err_to_py`'s `DecryptionFailed` mapping; a
    /// `padding="none"` alignment mistake stays the catalog's plain
    /// `ValueError`.
    #[pyo3(signature = (data=None))]
    fn finalize<'py>(
        &mut self,
        py: Python<'py>,
        data: Option<PyBuffer<u8>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let owned = match data {
            Some(buf) => buf.to_vec(py)?,
            None => Vec::new(),
        };
        let session = &mut self.session;
        let output = py
            .detach(|| session.close_out(&owned))
            .map_err(session_err_to_py)?;
        Ok(PyBytes::new(py, &output))
    }

    /// `mode`, `direction`, session state, and `iv` when present -- never
    /// key material (RFC Contracts: `__repr__`).
    fn __repr__(&self) -> String {
        match &self.iv {
            Some(iv) => {
                let iv_hex: String = iv.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "<TwofishSession mode={} direction={} state={} iv={}>",
                    self.mode,
                    self.direction.as_str(),
                    self.session.state_label(),
                    iv_hex,
                )
            }
            None => format!(
                "<TwofishSession mode={} direction={} state={}>",
                self.mode,
                self.direction.as_str(),
                self.session.state_label(),
            ),
        }
    }
}
