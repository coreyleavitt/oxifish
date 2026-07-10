//! `DecryptionError` and the engine-failure -> Python-exception mapping
//! (RFC 0001 slice 15, "Misuse machine + DecryptionError").
//!
//! Split out of `lib.rs` in slice 17 -- this is the one piece genuinely
//! shared by both `key.rs` (`TwofishKey::_encrypt_raw`/`_decrypt_raw`) and
//! `session.rs` (`TwofishSession::update`/`finalize`), so it gets its own
//! module rather than living in either.

use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::PyErr;

use crate::engine;

// ============================================================================
// DecryptionError (RFC 0001 slice 15, "Misuse machine + DecryptionError")
// ============================================================================
//
// Defined in Rust via `pyo3::create_exception!` rather than as a plain
// Python class in `python/oxifish/__init__.py` (where slice 7 originally
// pinned an *inert* placeholder of the same name) -- reconciled here in
// favor of the Rust-side mechanism, for a structural reason: the module
// boundary (RFC "Module boundary (pinned)") gives `TwofishKey` a Python
// facade (`TwofishKey.decrypt` in `__init__.py`) that could in principle
// catch a distinguishable Rust error and re-raise a Python-defined type,
// but `TwofishSession` has **no** Python wrapper at all -- it is "returned
// directly from Rust" per that same section -- so `TwofishSession.finalize()`
// has no facade call site to do that translation. Defining the exception
// type in Rust once and raising it directly from both `_decrypt_raw` (via
// `TwofishKey`'s raw methods) and `TwofishSession::finalize` (no
// intermediary) is the only mechanism that covers both surfaces uniformly.
// `python/oxifish/__init__.py` now re-exports this type instead of
// defining its own -- `oxifish.DecryptionError` is still, from Python's
// perspective, exactly what the RFC's Proposed Interface pseudocode shows:
// `class DecryptionError(ValueError): ...`, importable and catchable
// identically regardless of which language defines it.
create_exception!(
    _oxifish,
    DecryptionError,
    PyValueError,
    "Uniform padded-decrypt failure (RFC 0001 Contracts: normative security \
     scope). Fires only for invalid padding bytes or padded ciphertext \
     shorter than one block -- never for a caller-side `padding=\"none\"` \
     alignment mistake (that raises plain `ValueError`). One fixed message \
     closes the error-string side channel; no constant-time claim is made \
     (Twofish's key-dependent S-boxes are inherently non-constant-time)."
);

/// Map an engine failure onto its Python error type. `DecryptionFailed`
/// (RFC 0001 slice 15) raises [`DecryptionError`] -- the catalog's uniform
/// padded-decrypt failure type; every other variant (including
/// `UnalignedLength`, the `padding="none"` misalignment case, which must
/// NOT raise `DecryptionError` per the RFC Contracts) stays the plain
/// `ValueError` the old API has always raised for its (rare,
/// guard-clause-shadowed) error paths -- `DecryptionFailed` is the only
/// variant a `Padding::None` session can never produce (see
/// `engine::Session::close_out_decrypt`), so old-API callers (which
/// construct exclusively `Padding::None` sessions, per slice 6) are
/// unaffected by this branch.
#[inline]
pub(crate) fn engine_err_to_py(err: engine::EngineError) -> PyErr {
    match err {
        engine::EngineError::DecryptionFailed => DecryptionError::new_err(err.to_string()),
        other => PyValueError::new_err(other.to_string()),
    }
}

/// Map an engine failure onto `TwofishSession`'s error catalog entries:
/// `SessionFinalized` is `RuntimeError` (catalog: "`update`/`finalize`
/// after finalize"), distinct from every other engine failure, which stays
/// the plain `ValueError` mapping [`engine_err_to_py`] already uses.
#[inline]
pub(crate) fn session_err_to_py(err: engine::EngineError) -> PyErr {
    match err {
        engine::EngineError::SessionFinalized => PyRuntimeError::new_err(err.to_string()),
        other => engine_err_to_py(other),
    }
}
