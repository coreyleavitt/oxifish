//! Python bindings for the RustCrypto Twofish block cipher.
//!
//! This crate provides Python bindings via PyO3 for the Twofish block cipher,
//! exposing a session-oriented API (`TwofishKey` + `TwofishSession`) over
//! CBC, CTR, CFB, OFB, and ECB modes -- see RFC 0001
//! (`docs/rfcs/0001-twofish-session-api.md`) for the design rationale.
//! One-shot `encrypt`/`decrypt`, streaming sessions, and ECB's dedicated
//! factories all share the same internal buffering/padding engine
//! (`engine::Session`) below, so chunking behavior is identical regardless
//! of entry point.
//!
//! **Module layout (RFC 0001 slice 17, "Structural cleanup"):** this file
//! is deliberately thin -- the pymodule registration plus the one constant
//! genuinely shared across submodules. Everything else is one pyclass per
//! file: [`engine`] (the mode-agnostic buffering/padding core, pre-existing
//! since slice 3), `key` (`TwofishKey`), `session` (`TwofishSession`), and
//! `errors` (`DecryptionError` + the engine-failure -> Python-exception
//! mapping, shared by `key` and `session`).
mod engine;
mod errors;
mod key;
mod session;

use pyo3::prelude::*;

use errors::DecryptionError;
use key::TwofishKey;
use session::TwofishSession;

/// Block size in bytes, shared across `key` (IV validation/generation) and
/// exposed to Python as `_oxifish.BLOCK_SIZE`.
pub(crate) const BLOCK_SIZE_BYTES: usize = 16;

// ============================================================================
// Module definition
// ============================================================================

#[pymodule]
fn _oxifish(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TwofishKey>()?;
    m.add_class::<TwofishSession>()?;
    m.add("DecryptionError", m.py().get_type::<DecryptionError>())?;

    m.add("BLOCK_SIZE", BLOCK_SIZE_BYTES)?;

    Ok(())
}

// ============================================================================
// Zeroization: compile-time + drop-liveness verification (RFC 0001, slice 1)
// ============================================================================
//
// Memory-clearing itself is not observable without UB, so correctness is
// checked two ways instead of by inspecting cleared bytes:
//   1. A compile-time assertion that `Twofish` actually implements
//      `ZeroizeOnDrop` — this fails to *compile* if the `zeroize` feature
//      wiring across twofish/cipher ever regresses (e.g. someone drops the
//      feature flag from Cargo.toml again).
//   2. A drop-liveness test: construct and drop a `Twofish` key schedule and
//      confirm it doesn't panic. `Twofish` implements `ZeroizeOnDrop`, not
//      `Zeroize` — the marker trait says "this type's Drop impl already
//      zeroizes," so there's no separate `.zeroize()` call to make.
//
// `TwofishKey`-specific tests (construction, repr) live in `key.rs`'s own
// `#[cfg(test)] mod tests` -- this one stays here because it exercises the
// bare `twofish::Twofish` type, not any of this crate's own pyclasses.
//
// PyO3-boundary error paths (e.g. `TwofishKey::new`'s invalid-length
// `PyValueError`) panic outside an attached Python interpreter, which
// `cargo test` deliberately doesn't link/initialize (see the
// `extension-module` note in RFC 0001 slice 1) -- those are covered by
// pytest instead, matching `engine.rs`'s tests, which stick entirely to
// the pure-Rust `engine::Session`/`EngineError` types for the same reason.
#[cfg(test)]
mod tests {
    use static_assertions::assert_impl_all;
    use twofish::Twofish;
    use zeroize::ZeroizeOnDrop;

    assert_impl_all!(Twofish: ZeroizeOnDrop);

    #[test]
    fn twofish_key_schedule_drops_without_panic() {
        use cbc::cipher::KeyInit;

        let key = [0x42u8; 32];
        let cipher = Twofish::new_from_slice(&key).expect("32-byte key is valid");
        drop(cipher);
    }
}
