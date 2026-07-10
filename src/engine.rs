//! Internal mode engine (RFC 0001).
//!
//! A [`Session`] is the single streaming core behind every public entry
//! point: one-shot `encrypt`/`decrypt` and streaming `update`/`finalize`
//! all route through the same [`Session::ingest`] / [`Session::close_out`]
//! pair, making chunking invariance a structural guarantee rather than a
//! property of two independently correct implementations.
//!
//! The engine owns the three concerns the mode primitives must never see:
//!
//! - **Chunk buffering:** callers hand in arbitrary-length byte chunks;
//!   complete blocks are transformed eagerly and sub-block residue is held
//!   in a `pending` buffer, so a primitive is never driven with unaligned
//!   data.
//! - **Padding:** implemented once, mode-agnostically, against the final
//!   block at close-out. CBC and ECB share this path by construction; the
//!   `cbc` crate's own `encrypt_padded_mut`/`decrypt_padded_mut` helpers are
//!   deliberately not used (they would be a second padding implementation).
//! - **Session state:** `Fresh -> Streaming -> Finalized`. A finalized
//!   session rejects further input; close-out consumes the session even
//!   when it fails.
//!
//! Dispatch over the concrete RustCrypto mode objects is a plain `Send`
//! Rust enum ([`Transform`]) — no trait objects. Each non-ECB session owns
//! its own `Twofish` clone (inside the mode object), zeroized on the
//! session's own drop by the `zeroize`-feature `Drop` impls; ECB sessions
//! borrow the key's schedule via `Arc<Twofish>`.
//!
//! **Decrypt holdback.** A padded-decrypt session never emits the most
//! recently decrypted complete block from [`Session::ingest`] — it may
//! carry padding, and padding can only be identified/stripped once it is
//! known to be the *last* block (i.e. at [`Session::close_out`]). The held
//! block is plaintext at rest in the session for an arbitrary number of
//! `ingest` calls, so it lives in a dedicated zeroize-on-replace/drop slot
//! ([`HeldBlock`]) rather than a plain array. `padding = None` decrypt has
//! no notion of padding to withhold and instead flushes eagerly, checking
//! block alignment once at close-out (mirroring the encrypt-side check).
//!
//! **Branch-free unpad.** The four padded schemes (`Pkcs7`, `AnsiX923`,
//! `Iso7816`, `Zeros`) each validate/strip the held-back block with a
//! single pass over all 16 bytes — no early return keyed on the padding
//! content, so the *shape* of the validation work is identical whether the
//! padding is well-formed, corrupted, or absent. Only the final verdict
//! (accept/reject) branches, which is the one bit `DecryptionError`
//! intentionally reveals (see the RFC's Contracts: no constant-time claim
//! is made — Twofish's key-dependent S-boxes are not constant-time — this
//! closes the error-*string* side channel, nothing more).
//!
//! **Keystream modes (slice 5).** CTR and OFB are driven through
//! `StreamCipherCoreWrapper<CtrCore<..>>`/`StreamCipherCoreWrapper<OfbCore<..>>`
//! via the `StreamCipher::apply_keystream` API: genuinely byte-granular and
//! self-buffering mid-block keystream position internally, so [`Session::ingest`]
//! bypasses the block-buffering `pending` path entirely for these two
//! variants — every ingested byte is transformed and returned immediately,
//! and [`Session::close_out`] has nothing left to flush.
//!
//! **CFB (the bug fix).** CFB retains **one live** `cfb_mode::Encryptor`/
//! `Decryptor` per session — never the self-buffering `Buf*` variants — and
//! is driven through the *same* `pending`/`apply_blocks` path CBC uses:
//! complete blocks are transformed eagerly via `encrypt_blocks_inout_mut`/
//! `decrypt_blocks_inout_mut` against the one retained mode object, so the
//! feedback register advances exactly once per real block boundary,
//! regardless of how the caller chunks their input. This is structurally
//! why the old bug (sub-16-byte chunks freezing the register; larger
//! unaligned chunks deriving feedback from a misaligned window) cannot
//! recur: the primitive is *never* invoked with anything but a full block,
//! because the engine — not the caller's chunk boundaries — decides when a
//! block is complete. Unlike CBC/ECB, CFB has no padding (it is a stream
//! mode): close-out resolves any sub-block residue by generating one more
//! keystream block from the current register (`encrypt_block_mut`/
//! `decrypt_block_mut` on a zero-padded block) and keeping only the bytes
//! the caller actually sent — no alignment error; arbitrary total lengths,
//! including zero, are valid for all three stream modes.

use core::fmt;

use std::sync::Arc;

use cipher::consts::U16;
use cipher::inout::InOutBuf;
use cipher::{Block, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut};
use twofish::Twofish;
use zeroize::{Zeroize, Zeroizing};

/// Twofish block size in bytes.
pub(crate) const BLOCK_SIZE: usize = 16;

/// Engine-level padding policy, decided at session construction.
///
/// RFC 0001 slice 6 re-routes the *old* Python API's one-shot functions
/// and streaming pyclasses through this engine, but the old API has no
/// padding-selection surface of its own for CBC/ECB (callers pad/unpad
/// externally via the module-level `pad`/`unpad` functions); every session
/// it constructs uses `Padding::None`. The four padded variants are
/// exercised thoroughly by `cargo test` (see the padding/unpad test suite
/// below); slice 8 makes them reachable from Python via
/// `TwofishKey._encrypt_raw`/`_decrypt_raw`'s `padding` argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Padding {
    Pkcs7,
    AnsiX923,
    Iso7816,
    Zeros,
    None,
}

/// Engine-level failures. The PyO3 layer maps these onto the RFC's
/// normative error catalog; `Display` already produces the catalog strings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EngineError {
    /// `ingest`/`close_out` called on a finalized session.
    SessionFinalized,
    /// `Padding::None` close-out with a total length that is not a
    /// multiple of the block size. Carries the total accumulated length.
    UnalignedLength { total: usize },
    /// Padded-decrypt close-out failure: invalid padding bytes, a total
    /// length that leaves a non-block-aligned remainder, or a total
    /// shorter than one block (including zero bytes). The RFC's single
    /// error-string channel — deliberately carries no diagnostic payload,
    /// so it cannot itself become a side channel.
    DecryptionFailed,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::SessionFinalized => f.write_str("session is already finalized"),
            EngineError::UnalignedLength { total } => write!(
                f,
                "data length ({total}) is not a multiple of the block size ({BLOCK_SIZE})"
            ),
            EngineError::DecryptionFailed => {
                f.write_str("decryption failed: invalid or corrupted ciphertext")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// Mode dispatch: a plain `Send` enum over the concrete RustCrypto mode
/// objects, one live instance retained per session (IV/keystream state
/// chains across calls) — the RFC's "eight variants": four block-buffered
/// pairs (CBC/ECB × enc/dec) below, plus CFB's pair and CTR/OFB (each a
/// single variant — encrypt and decrypt are the identical XOR operation for
/// a synchronous stream cipher, so no separate direction object exists).
enum Transform {
    /// CBC encryption via an incrementally driven `cbc::Encryptor`.
    CbcEnc(cbc::Encryptor<Twofish>),
    /// CBC decryption via an incrementally driven `cbc::Decryptor`.
    CbcDec(cbc::Decryptor<Twofish>),
    /// ECB encryption directly on the key's shared schedule.
    EcbEnc(Arc<Twofish>),
    /// ECB decryption directly on the key's shared schedule.
    EcbDec(Arc<Twofish>),
    /// CFB encryption via an incrementally driven, live-register
    /// `cfb_mode::Encryptor` (see module docs: CFB (the bug fix)).
    CfbEnc(cfb_mode::Encryptor<Twofish>),
    /// CFB decryption via an incrementally driven, live-register
    /// `cfb_mode::Decryptor`.
    CfbDec(cfb_mode::Decryptor<Twofish>),
    /// CTR keystream, `Ctr128BE`: the full 16-byte IV is a single
    /// big-endian 128-bit initial counter block (not a nonce+counter
    /// split), incremented once per block by `StreamCipherCoreWrapper`.
    Ctr(ctr::Ctr128BE<Twofish>),
    /// OFB keystream via `StreamCipherCoreWrapper<OfbCore<..>>`.
    Ofb(ofb::Ofb<Twofish>),
}

/// How a [`Transform`] variant is driven — determines which of
/// [`Session::ingest`]/[`Session::close_out`]'s three code paths applies.
/// Computed fresh from `&Transform` (a plain tag, `Copy`) rather than
/// matched on directly, so callers needing `&mut self` elsewhere are never
/// blocked by a live borrow of `self.transform`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// CBC/ECB encrypt: pending-buffered, padding applied at close-out.
    BlockPaddedEnc,
    /// CBC/ECB decrypt: pending-buffered with one-block holdback (when
    /// padded), padding verified/stripped at close-out.
    BlockPaddedDec,
    /// CFB encrypt: pending-buffered, no padding, no holdback; residue
    /// resolved at close-out via one partial keystream block.
    FeedbackEnc,
    /// CFB decrypt: symmetric to `FeedbackEnc`.
    FeedbackDec,
    /// CTR/OFB: byte-granular, no buffering, no close-out work.
    Stream,
}

impl Transform {
    /// Transform `buf` (whose length must be a multiple of the block size)
    /// in place, one incremental multi-block call on the retained mode
    /// object. Used by the `BlockPadded*`/`Feedback*` kinds only — `Stream`
    /// transforms never buffer to block boundaries (see
    /// [`Transform::apply_stream`]).
    fn apply_blocks(&mut self, buf: &mut [u8]) {
        // Real `assert!`s, not `debug_assert!` (F17): these guard the exact
        // invariant `into_chunks` relies on. A violation here would not
        // panic in release builds under `debug_assert!` -- it would instead
        // silently leave `tail` (part of the caller's buffer) untouched by
        // the transform below, corrupting output rather than failing.
        assert_eq!(
            buf.len() % BLOCK_SIZE,
            0,
            "apply_blocks: buf.len() must be a multiple of BLOCK_SIZE"
        );
        let (blocks, tail) = InOutBuf::from(buf).into_chunks::<U16>();
        assert!(
            tail.is_empty(),
            "apply_blocks: unexpected non-block-aligned tail from into_chunks"
        );
        match self {
            Transform::CbcEnc(enc) => enc.encrypt_blocks_inout_mut(blocks),
            Transform::CbcDec(dec) => dec.decrypt_blocks_inout_mut(blocks),
            Transform::EcbEnc(cipher) => cipher.encrypt_blocks_inout(blocks),
            Transform::EcbDec(cipher) => cipher.decrypt_blocks_inout(blocks),
            Transform::CfbEnc(enc) => enc.encrypt_blocks_inout_mut(blocks),
            Transform::CfbDec(dec) => dec.decrypt_blocks_inout_mut(blocks),
            Transform::Ctr(_) | Transform::Ofb(_) => {
                unreachable!("Stream-kind transforms never reach apply_blocks")
            }
        }
    }

    /// Apply the keystream to `buf` in place, byte-granular, self-buffering
    /// mid-block position across calls. `Stream`-kind transforms only.
    fn apply_stream(&mut self, buf: &mut [u8]) {
        use cipher::StreamCipher;
        match self {
            Transform::Ctr(c) => c.apply_keystream(buf),
            Transform::Ofb(c) => c.apply_keystream(buf),
            _ => unreachable!("apply_stream is only called for Stream-kind transforms"),
        }
    }

    /// One partial keystream block for CFB close-out: zero-pad `pending`'s
    /// residue to a full block, run it through the live retained
    /// `Encryptor`/`Decryptor` (one ordinary `encrypt_block_mut`/
    /// `decrypt_block_mut` call — the register still advances internally,
    /// but the session is finalized immediately afterwards so that never
    /// matters), and write back only the first `residue.len()` bytes.
    /// `FeedbackEnc`/`FeedbackDec` kinds only.
    fn apply_partial_feedback_block(&mut self, residue: &[u8]) -> [u8; BLOCK_SIZE] {
        debug_assert!(!residue.is_empty() && residue.len() < BLOCK_SIZE);
        let mut block = Block::<Twofish>::default();
        block[..residue.len()].copy_from_slice(residue);
        match self {
            Transform::CfbEnc(enc) => enc.encrypt_block_mut(&mut block),
            Transform::CfbDec(dec) => dec.decrypt_block_mut(&mut block),
            _ => unreachable!("apply_partial_feedback_block is only called for Feedback kinds"),
        }
        let mut out = [0u8; BLOCK_SIZE];
        out.copy_from_slice(&block);
        // `block` holds real plaintext bytes (encrypt: the caller's
        // residue; decrypt: the recovered plaintext) XORed with keystream
        // -- an intermediate copy the engine itself created, now fully
        // consumed into `out`. Scrub it before it drops, matching the
        // module's zeroization discipline.
        block.as_mut_slice().zeroize();
        out
    }

    /// This transform's [`Kind`] — see its docs for what each maps to.
    fn kind(&self) -> Kind {
        match self {
            Transform::CbcEnc(_) | Transform::EcbEnc(_) => Kind::BlockPaddedEnc,
            Transform::CbcDec(_) | Transform::EcbDec(_) => Kind::BlockPaddedDec,
            Transform::CfbEnc(_) => Kind::FeedbackEnc,
            Transform::CfbDec(_) => Kind::FeedbackDec,
            Transform::Ctr(_) | Transform::Ofb(_) => Kind::Stream,
        }
    }
}

/// Sub-block residue buffer. Holds at most `BLOCK_SIZE - 1` bytes of
/// not-yet-transformed input (plaintext on the encrypt path), zeroized on
/// overwrite and on drop.
struct Pending {
    buf: [u8; BLOCK_SIZE],
    len: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            buf: [0u8; BLOCK_SIZE],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Append bytes; the caller guarantees the residue invariant
    /// (`len` stays strictly below `BLOCK_SIZE`).
    fn extend(&mut self, bytes: &[u8]) {
        // Real `assert!`, not `debug_assert!` (F17): a violation would
        // silently truncate/misalign `bytes` into `self.buf` in release
        // builds rather than fail, corrupting subsequent output.
        assert!(
            self.len + bytes.len() < BLOCK_SIZE,
            "Pending::extend: residue must stay below one block"
        );
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// Zeroize and empty the buffer.
    fn clear(&mut self) {
        self.buf.zeroize();
        self.len = 0;
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Held-back decrypted block for padded-decrypt sessions (see module docs:
/// decrypt holdback). At most one complete plaintext block is withheld at
/// a time — it may carry padding, resolved only at `close_out`. Zeroized
/// on replacement and on drop, since it is plaintext sitting at rest for
/// an arbitrary number of `ingest` calls.
struct HeldBlock {
    block: [u8; BLOCK_SIZE],
    present: bool,
}

impl HeldBlock {
    fn empty() -> Self {
        Self {
            block: [0u8; BLOCK_SIZE],
            present: false,
        }
    }

    /// Store `new_block`, returning the previously held block (if any).
    fn replace(&mut self, new_block: [u8; BLOCK_SIZE]) -> Option<[u8; BLOCK_SIZE]> {
        let old = self.present.then_some(self.block);
        self.block = new_block;
        self.present = true;
        old
    }

    /// Take the held block, zeroizing the slot it occupied.
    fn take(&mut self) -> Option<[u8; BLOCK_SIZE]> {
        if !self.present {
            return None;
        }
        let block = self.block;
        self.block.zeroize();
        self.present = false;
        Some(block)
    }
}

impl Drop for HeldBlock {
    fn drop(&mut self) {
        self.block.zeroize();
    }
}

/// Session lifecycle: `Fresh -> Streaming` on first input,
/// `-> Finalized` on close-out (successful or not).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Fresh,
    Streaming,
    Finalized,
}

/// The streaming session core: arbitrary-length chunks in, transformed
/// complete blocks out, padding applied at close-out.
pub(crate) struct Session {
    transform: Transform,
    padding: Padding,
    pending: Pending,
    /// Most recently decrypted complete block, withheld from `ingest`'s
    /// output on padded-decrypt sessions only (see module docs). Unused
    /// (always empty) on encrypt sessions and `padding = None` decrypt.
    held: HeldBlock,
    /// Total bytes ingested, for the `Padding::None` alignment diagnostic.
    total_len: usize,
    state: State,
}

impl Session {
    fn new(transform: Transform, padding: Padding) -> Self {
        Self {
            transform,
            padding,
            pending: Pending::new(),
            held: HeldBlock::empty(),
            total_len: 0,
            state: State::Fresh,
        }
    }

    /// CBC encrypt session. Takes ownership of the session's own `Twofish`
    /// clone (per-session zeroization; see module docs).
    pub(crate) fn cbc_encryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE], padding: Padding) -> Self {
        use cipher::InnerIvInit;
        let enc = cbc::Encryptor::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        Self::new(Transform::CbcEnc(enc), padding)
    }

    /// CBC decrypt session. Takes ownership of the session's own `Twofish`
    /// clone (per-session zeroization; see module docs).
    pub(crate) fn cbc_decryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE], padding: Padding) -> Self {
        use cipher::InnerIvInit;
        let dec = cbc::Decryptor::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        Self::new(Transform::CbcDec(dec), padding)
    }

    /// ECB encrypt session, borrowing the key's shared schedule.
    pub(crate) fn ecb_encryptor(cipher: Arc<Twofish>, padding: Padding) -> Self {
        Self::new(Transform::EcbEnc(cipher), padding)
    }

    /// ECB decrypt session, borrowing the key's shared schedule.
    pub(crate) fn ecb_decryptor(cipher: Arc<Twofish>, padding: Padding) -> Self {
        Self::new(Transform::EcbDec(cipher), padding)
    }

    /// CFB encrypt session: one live retained `cfb_mode::Encryptor` (see
    /// module docs: CFB (the bug fix)). Stream mode — never padded.
    pub(crate) fn cfb_encryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        use cipher::InnerIvInit;
        let enc = cfb_mode::Encryptor::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        Self::new(Transform::CfbEnc(enc), Padding::None)
    }

    /// CFB decrypt session: one live retained `cfb_mode::Decryptor`.
    /// Stream mode — never padded.
    pub(crate) fn cfb_decryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        use cipher::InnerIvInit;
        let dec = cfb_mode::Decryptor::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        Self::new(Transform::CfbDec(dec), Padding::None)
    }

    /// CTR encrypt session (`Ctr128BE`; see [`Transform::Ctr`] for the IV
    /// contract). Encrypt and decrypt construct the identical keystream
    /// object — CTR is its own inverse — kept as two named factories for
    /// symmetry with the other modes and so a future direction property has
    /// an obvious construction site to read it from.
    pub(crate) fn ctr_encryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        Self::new(Transform::Ctr(Self::make_ctr(cipher, iv)), Padding::None)
    }

    /// CTR decrypt session. See [`Session::ctr_encryptor`].
    pub(crate) fn ctr_decryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        Self::new(Transform::Ctr(Self::make_ctr(cipher, iv)), Padding::None)
    }

    fn make_ctr(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> ctr::Ctr128BE<Twofish> {
        use cipher::{InnerIvInit, StreamCipherCoreWrapper};
        let core = ctr::CtrCore::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        StreamCipherCoreWrapper::from_core(core)
    }

    /// OFB encrypt session. See [`Session::ctr_encryptor`] re: the shared
    /// encrypt/decrypt construction (OFB is likewise its own inverse).
    pub(crate) fn ofb_encryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        Self::new(Transform::Ofb(Self::make_ofb(cipher, iv)), Padding::None)
    }

    /// OFB decrypt session. See [`Session::ctr_encryptor`].
    pub(crate) fn ofb_decryptor(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> Self {
        Self::new(Transform::Ofb(Self::make_ofb(cipher, iv)), Padding::None)
    }

    fn make_ofb(cipher: Twofish, iv: &[u8; BLOCK_SIZE]) -> ofb::Ofb<Twofish> {
        use cipher::{InnerIvInit, StreamCipherCoreWrapper};
        let core = ofb::OfbCore::inner_iv_init(cipher, Block::<Twofish>::from_slice(iv));
        StreamCipherCoreWrapper::from_core(core)
    }

    /// Human-readable session-state label for `TwofishSession.__repr__`
    /// (RFC 0001 Contracts: `__repr__` -- "mode, direction, session state,
    /// and iv"). Exposed as a plain string rather than [`State`] itself,
    /// since the PyO3 layer has no reason to match on the enum.
    pub(crate) fn state_label(&self) -> &'static str {
        match self.state {
            State::Fresh => "fresh",
            State::Streaming => "streaming",
            State::Finalized => "finalized",
        }
    }

    /// Ingest one chunk: transform and return complete blocks, buffering
    /// sub-block residue. Returns an empty vec while a partial block
    /// accumulates.
    ///
    /// Encrypt sessions and `padding = None` decrypt flush eagerly: every
    /// block this call completes is returned. Padded-decrypt sessions
    /// additionally withhold the most recently decrypted block (see
    /// [`Session::holds_back`]): N newly completed blocks contribute N-1
    /// to the return value, with the Nth becoming the new held block.
    ///
    /// `Stream`-kind sessions (CTR/OFB) bypass all of the above: no
    /// blocking, no holdback, byte-granular in and out via
    /// [`Transform::apply_stream`].
    pub(crate) fn ingest(&mut self, chunk: &[u8]) -> Result<Vec<u8>, EngineError> {
        self.begin()?;
        self.total_len += chunk.len();

        if self.transform.kind() == Kind::Stream {
            let mut out = chunk.to_vec();
            self.transform.apply_stream(&mut out);
            return Ok(out);
        }

        let complete = (self.pending.len + chunk.len()) / BLOCK_SIZE;
        if complete == 0 {
            self.pending.extend(chunk);
            return Ok(Vec::new());
        }

        let emit_len = complete * BLOCK_SIZE;
        let take = emit_len - self.pending.len;
        let mut out = Vec::with_capacity(emit_len);
        out.extend_from_slice(self.pending.as_slice());
        out.extend_from_slice(&chunk[..take]);
        self.pending.clear();
        self.pending.extend(&chunk[take..]);

        self.transform.apply_blocks(&mut out);

        if self.holds_back() {
            Ok(self.release_ready_blocks(out))
        } else {
            Ok(out)
        }
    }

    /// Whether this session withholds its most recently transformed block
    /// from `ingest`'s return value: padded-decrypt (`BlockPaddedDec`)
    /// sessions only. Encrypt (no padding to resolve early), `padding =
    /// None` decrypt (no padding to withhold for), and CFB (a stream mode —
    /// always constructed with `Padding::None`, see [`Session::cfb_encryptor`])
    /// all flush eagerly.
    fn holds_back(&self) -> bool {
        self.transform.kind() == Kind::BlockPaddedDec && self.padding != Padding::None
    }

    /// Combine this call's freshly decrypted blocks with any
    /// previously held block, hold back the new last block, and return
    /// the rest. `new_blocks` must be non-empty and block-aligned (the
    /// only caller, `ingest`, guarantees this via `complete > 0`).
    fn release_ready_blocks(&mut self, mut new_blocks: Vec<u8>) -> Vec<u8> {
        debug_assert!(!new_blocks.is_empty());
        debug_assert_eq!(new_blocks.len() % BLOCK_SIZE, 0);

        let split_at = new_blocks.len() - BLOCK_SIZE;
        let mut new_held = [0u8; BLOCK_SIZE];
        new_held.copy_from_slice(&new_blocks[split_at..]);
        // The tail we just copied out is about to become spare capacity
        // that `truncate` leaves untouched (and un-zeroized) in the Vec's
        // backing allocation -- scrub the plaintext duplicate before it's
        // orphaned there.
        new_blocks[split_at..].zeroize();
        new_blocks.truncate(split_at);

        // `[u8; BLOCK_SIZE]` is `Copy`, so `new_held` is copied (not
        // moved) into `self.held`; the local binding survives this call
        // and must be scrubbed explicitly once its copy is safely stored.
        let previous = self.held.replace(new_held);
        new_held.zeroize();

        match previous {
            Some(mut previous) => {
                let mut out = Vec::with_capacity(BLOCK_SIZE + new_blocks.len());
                out.extend_from_slice(&previous);
                out.extend_from_slice(&new_blocks);
                previous.zeroize();
                out
            }
            None => new_blocks,
        }
    }

    /// `Fresh|Streaming -> Streaming`; finalized sessions reject input.
    fn begin(&mut self) -> Result<(), EngineError> {
        match self.state {
            State::Finalized => Err(EngineError::SessionFinalized),
            State::Fresh | State::Streaming => {
                self.state = State::Streaming;
                Ok(())
            }
        }
    }

    /// Ingest an optional final chunk, then close the session out:
    /// flush the residue through the mode's close-out policy and consume
    /// the session. Close-out consumes the session even on failure.
    ///
    /// Dispatches on [`Transform::kind`]: `BlockPaddedEnc`/`BlockPaddedDec`
    /// apply/verify padding as before slice 5; `FeedbackEnc`/`FeedbackDec`
    /// (CFB) resolve any sub-block residue via one partial keystream block,
    /// never erroring on misalignment (see [`Session::close_out_feedback`]);
    /// `Stream` (CTR/OFB) has nothing left to do — `ingest` already emitted
    /// every byte.
    pub(crate) fn close_out(&mut self, chunk: &[u8]) -> Result<Vec<u8>, EngineError> {
        let mut out = self.ingest(chunk)?;
        self.state = State::Finalized;
        match self.transform.kind() {
            Kind::BlockPaddedDec => self.close_out_decrypt(&mut out)?,
            Kind::BlockPaddedEnc => {
                if let Some(mut block) = self.padding_block()? {
                    self.transform.apply_blocks(&mut block);
                    out.extend_from_slice(&block);
                }
            }
            Kind::FeedbackEnc | Kind::FeedbackDec => self.close_out_feedback(&mut out),
            Kind::Stream => {}
        }
        Ok(out)
    }

    /// CFB close-out: resolve any sub-block `pending` residue by generating
    /// one partial keystream block from the live register (see
    /// [`Transform::apply_partial_feedback_block`]) and appending exactly
    /// the residue's own length of output. A no-op when the total was
    /// already block-aligned (including zero bytes). Unlike
    /// [`Session::close_out_decrypt`], no length is ever invalid — CFB is a
    /// stream mode.
    fn close_out_feedback(&mut self, out: &mut Vec<u8>) {
        if self.pending.len == 0 {
            return;
        }
        let n = self.pending.len;
        let mut result = self
            .transform
            .apply_partial_feedback_block(self.pending.as_slice());
        self.pending.clear();
        out.extend_from_slice(&result[..n]);
        result.zeroize();
    }

    /// Decrypt-side close-out: resolve the held-back block (padded) or
    /// verify final alignment (`padding = None`), appending any resulting
    /// plaintext to `out`.
    ///
    /// A non-empty `pending` residue at this point means the total
    /// ciphertext was not block-aligned — always invalid, since genuine
    /// ciphertext from a block cipher is exact multiples of the block
    /// size. For `padding = None` that is a caller-side usage error
    /// (`UnalignedLength`, mirroring the encrypt-side check); for the
    /// padded schemes it falls under the single `DecryptionFailed` channel
    /// (RFC: "invalid or corrupted ciphertext" covers any shape of
    /// corruption, not only bad padding bytes).
    fn close_out_decrypt(&mut self, out: &mut Vec<u8>) -> Result<(), EngineError> {
        if self.pending.len != 0 {
            return Err(if self.padding == Padding::None {
                EngineError::UnalignedLength {
                    total: self.total_len,
                }
            } else {
                EngineError::DecryptionFailed
            });
        }

        if self.padding == Padding::None {
            return Ok(());
        }

        // Too short: no complete block was ever decrypted (total < one
        // block, including zero bytes) — the RFC's explicit "shorter than
        // one block" DecryptionError trigger.
        //
        // `block` is the final padded plaintext block, held in a local now
        // that `HeldBlock::take` has zeroized its slot. Wrapped in
        // `Zeroizing` so this copy is scrubbed on *every* exit path --
        // including the `?` below on an `unpad` failure -- rather than only
        // after a manual zeroize placed after a fallible call.
        let block = Zeroizing::new(self.held.take().ok_or(EngineError::DecryptionFailed)?);
        let unpadded = unpad(&block, self.padding)?;
        out.extend_from_slice(unpadded);
        Ok(())
    }

    /// The single, mode-agnostic padding implementation (encrypt side):
    /// drain the residue into the final padded block, or `None` when the
    /// policy emits nothing for an aligned tail.
    fn padding_block(&mut self) -> Result<Option<[u8; BLOCK_SIZE]>, EngineError> {
        let len = self.pending.len;
        let pad_len = BLOCK_SIZE - len;
        let mut block = [0u8; BLOCK_SIZE];
        block[..len].copy_from_slice(self.pending.as_slice());
        self.pending.clear();

        match self.padding {
            Padding::Pkcs7 => {
                block[len..].fill(pad_len as u8);
                Ok(Some(block))
            }
            Padding::AnsiX923 => {
                block[BLOCK_SIZE - 1] = pad_len as u8;
                Ok(Some(block))
            }
            Padding::Iso7816 => {
                block[len] = 0x80;
                Ok(Some(block))
            }
            Padding::Zeros => {
                if len == 0 {
                    Ok(None)
                } else {
                    Ok(Some(block))
                }
            }
            Padding::None => {
                if len == 0 {
                    Ok(None)
                } else {
                    block.zeroize();
                    Err(EngineError::UnalignedLength {
                        total: self.total_len,
                    })
                }
            }
        }
    }
}

/// Turn a boolean predicate into an all-ones/all-zeros mask byte, the
/// building block the unpad routines below use in place of `if`/`match` on
/// padding content: `0xFF` when `b`, `0x00` otherwise.
#[inline]
fn ct_mask(b: bool) -> u8 {
    (b as u8).wrapping_neg()
}

/// The single, mode-agnostic unpad implementation (decrypt side): validate
/// and strip the padding of a held-back final block. Shared by CBC and ECB
/// — the same padding state machine `padding_block` implements for
/// encrypt, run in reverse. Each of the three schemes that can fail
/// (`Pkcs7`, `AnsiX923`, `Iso7816`) scans the full 16 bytes unconditionally
/// before producing a verdict (see module docs: Branch-free unpad); the
/// single verdict branch at the end is the one bit `DecryptionError`
/// intentionally reveals. `Zeros` cannot fail (see its own docs) and
/// `None` never reaches this function (`close_out_decrypt` returns before
/// calling it).
fn unpad(block: &[u8; BLOCK_SIZE], padding: Padding) -> Result<&[u8], EngineError> {
    match padding {
        Padding::Pkcs7 => unpad_pkcs7(block),
        Padding::AnsiX923 => unpad_ansix923(block),
        Padding::Iso7816 => unpad_iso7816(block),
        Padding::Zeros => Ok(unpad_zeros(block)),
        Padding::None => unreachable!("Padding::None has no holdback/unpad path"),
    }
}

/// PKCS#7: the last byte `n` is both the pad length and the pad byte
/// value; valid iff `1 <= n <= 16` and the last `n` bytes all equal `n`.
/// The scheme's own length byte, `n`, is public before validation (it is
/// simply `block[15]`), so branching to compute it is not a side channel;
/// what must stay branch-free is *validating* the candidate padding
/// against the rest of the block.
fn unpad_pkcs7(block: &[u8; BLOCK_SIZE]) -> Result<&[u8], EngineError> {
    let n = block[BLOCK_SIZE - 1];
    let in_range = ct_mask(n >= 1) & ct_mask(n <= BLOCK_SIZE as u8);

    let mut mismatch = 0u8;
    for (i, &byte) in block.iter().enumerate() {
        let pos_from_end = (BLOCK_SIZE - i) as u8; // 16, 15, ..., 1
        let is_pad_pos = ct_mask(pos_from_end <= n);
        mismatch |= is_pad_pos & (byte ^ n);
    }

    if in_range & ct_mask(mismatch == 0) == 0xFF {
        Ok(&block[..BLOCK_SIZE - n as usize])
    } else {
        Err(EngineError::DecryptionFailed)
    }
}

/// ANSI X9.23: the last byte `n` is the pad length (`1..=16`); the `n - 1`
/// bytes preceding it are zero. Same one-pass-over-16-bytes shape as
/// PKCS#7; checking the length byte against itself is a no-op that keeps
/// the loop uniform rather than a special case.
fn unpad_ansix923(block: &[u8; BLOCK_SIZE]) -> Result<&[u8], EngineError> {
    let n = block[BLOCK_SIZE - 1];
    let in_range = ct_mask(n >= 1) & ct_mask(n <= BLOCK_SIZE as u8);

    let mut mismatch = 0u8;
    for (i, &byte) in block.iter().enumerate() {
        let pos_from_end = (BLOCK_SIZE - i) as u8;
        let is_pad_pos = ct_mask(pos_from_end <= n);
        let is_last_byte = ct_mask(pos_from_end == 1);
        let expected = is_last_byte & n; // n at the last byte, 0 elsewhere
        mismatch |= is_pad_pos & (byte ^ expected);
    }

    if in_range & ct_mask(mismatch == 0) == 0xFF {
        Ok(&block[..BLOCK_SIZE - n as usize])
    } else {
        Err(EngineError::DecryptionFailed)
    }
}

/// ISO/IEC 7816-4: a single `0x80` marker byte followed by zero or more
/// `0x00` bytes, scanned from the end. Unlike PKCS#7/ANSI X9.23 the pad
/// length isn't a fixed byte position — it's discovered by the scan — so
/// the loop tracks two running masks instead of computing `n` up front:
/// `found` (the marker has been located) and `bad` (a byte violated the
/// expected zero-run before the marker was found). Both are updated with
/// the same unconditional per-byte step for all 16 bytes; once `found`
/// flips to `0xFF`, `active` gates out every later byte so bytes before
/// the padding region (real plaintext) never influence the verdict.
fn unpad_iso7816(block: &[u8; BLOCK_SIZE]) -> Result<&[u8], EngineError> {
    let mut found = 0u8;
    let mut bad = 0u8;
    let mut n = 0u8;

    for d in 0..BLOCK_SIZE as u8 {
        let byte = block[BLOCK_SIZE - 1 - d as usize];
        let is_marker = ct_mask(byte == 0x80);
        let is_zero = ct_mask(byte == 0x00);
        let active = !found;

        let newly_found = active & is_marker;
        found |= newly_found;
        n |= newly_found & (d + 1);
        bad |= active & !is_marker & !is_zero;
    }

    if found & !bad == 0xFF {
        Ok(&block[..BLOCK_SIZE - n as usize])
    } else {
        Err(EngineError::DecryptionFailed)
    }
}

/// "Zeros": strip 0-15 trailing zero bytes from the held-back block.
/// Never fails — a block of all payload (aligned original message, no
/// padding was ever added) is indistinguishable from one that legitimately
/// ends in zero bytes, which is exactly the RFC's documented ambiguity for
/// this scheme (interop-only). With no failure mode there is no verdict to
/// protect, so this scan is the ordinary early-exit version.
fn unpad_zeros(block: &[u8; BLOCK_SIZE]) -> &[u8] {
    let mut len = BLOCK_SIZE;
    while len > 0 && block[len - 1] == 0 {
        len -= 1;
    }
    &block[..len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    const KEY: [u8; 32] = [0x42; 32];
    const IV: [u8; BLOCK_SIZE] = [0x24; BLOCK_SIZE];

    fn cipher() -> Twofish {
        Twofish::new_from_slice(&KEY).expect("32-byte key is valid")
    }

    fn cbc_session(padding: Padding) -> Session {
        Session::cbc_encryptor(cipher(), &IV, padding)
    }

    fn cbc_decrypt_session(padding: Padding) -> Session {
        Session::cbc_decryptor(cipher(), &IV, padding)
    }

    /// Independent CBC reference: manual XOR chaining over raw
    /// `Twofish::encrypt_block`, no mode crate involved.
    fn reference_cbc_encrypt(padded: &[u8]) -> Vec<u8> {
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        let cipher = cipher();
        let mut prev = IV;
        let mut out = Vec::with_capacity(padded.len());
        for chunk in padded.chunks(BLOCK_SIZE) {
            let mut block = Block::<Twofish>::default();
            for (b, (&c, &p)) in block.iter_mut().zip(chunk.iter().zip(prev.iter())) {
                *b = c ^ p;
            }
            cipher.encrypt_block(&mut block);
            prev.copy_from_slice(&block);
            out.extend_from_slice(&block);
        }
        out
    }

    /// Independent CBC decrypt reference: manual un-chaining over raw
    /// `Twofish::decrypt_block`, no mode crate involved.
    fn reference_cbc_decrypt(ciphertext: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len() % BLOCK_SIZE, 0);
        let cipher = cipher();
        let mut prev = IV;
        let mut out = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let mut block = Block::<Twofish>::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for (b, &p) in block.iter_mut().zip(prev.iter()) {
                *b ^= p;
            }
            prev.copy_from_slice(chunk);
            out.extend_from_slice(&block);
        }
        out
    }

    /// Independent PKCS#7 reference padding.
    fn reference_pkcs7(msg: &[u8]) -> Vec<u8> {
        let pad = BLOCK_SIZE - msg.len() % BLOCK_SIZE;
        let mut padded = msg.to_vec();
        padded.extend(std::iter::repeat(pad as u8).take(pad));
        padded
    }

    fn ecb_session(padding: Padding) -> Session {
        Session::ecb_encryptor(Arc::new(cipher()), padding)
    }

    fn ecb_decrypt_session(padding: Padding) -> Session {
        Session::ecb_decryptor(Arc::new(cipher()), padding)
    }

    /// Independent ECB reference: raw per-block `Twofish::encrypt_block`.
    fn reference_ecb_encrypt(padded: &[u8]) -> Vec<u8> {
        assert_eq!(padded.len() % BLOCK_SIZE, 0);
        let cipher = cipher();
        let mut out = Vec::with_capacity(padded.len());
        for chunk in padded.chunks(BLOCK_SIZE) {
            let mut block = Block::<Twofish>::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        out
    }

    /// Drive `msg` through a session as the given chunk partition
    /// (the last chunk goes in via `close_out`), concatenating output.
    fn run_partition(mut session: Session, msg: &[u8], sizes: &[usize]) -> Vec<u8> {
        assert_eq!(sizes.iter().sum::<usize>(), msg.len());
        let mut out = Vec::new();
        let mut offset = 0;
        for (i, &size) in sizes.iter().enumerate() {
            let chunk = &msg[offset..offset + size];
            offset += size;
            if i + 1 == sizes.len() {
                out.extend(session.close_out(chunk).expect("close_out succeeds"));
            } else {
                out.extend(session.ingest(chunk).expect("ingest succeeds"));
            }
        }
        out
    }

    #[test]
    fn ecb_none_padding_single_block_matches_raw_block_encrypt() {
        let block = [0x3Cu8; BLOCK_SIZE];
        let mut session = ecb_session(Padding::None);
        let out = session.close_out(&block).expect("aligned block");
        assert_eq!(out, reference_ecb_encrypt(&block));
    }

    #[test]
    fn chunking_invariance_cbc_matches_one_shot() {
        let msg: Vec<u8> = (0u8..40).collect();
        let one_shot = run_partition(cbc_session(Padding::Pkcs7), &msg, &[40]);
        assert_eq!(one_shot, reference_cbc_encrypt(&reference_pkcs7(&msg)));

        let patterns: &[&[usize]] = &[
            &[1; 40],
            &[15, 1, 17, 7],
            &[16, 16, 8],
            &[5, 0, 11, 7, 17],
            &[39, 1],
            &[40],
        ];
        for sizes in patterns {
            let out = run_partition(cbc_session(Padding::Pkcs7), &msg, sizes);
            assert_eq!(out, one_shot, "partition {sizes:?}");
        }
    }

    #[test]
    fn chunking_invariance_ecb_matches_one_shot() {
        let msg: Vec<u8> = (100u8..140).collect();
        let one_shot = run_partition(ecb_session(Padding::Pkcs7), &msg, &[40]);
        assert_eq!(one_shot, reference_ecb_encrypt(&reference_pkcs7(&msg)));

        let patterns: &[&[usize]] = &[&[1; 40], &[15, 1, 17, 7], &[16, 16, 8], &[39, 1]];
        for sizes in patterns {
            let out = run_partition(ecb_session(Padding::Pkcs7), &msg, sizes);
            assert_eq!(out, one_shot, "partition {sizes:?}");
        }
    }

    #[test]
    fn ingest_buffers_sub_block_chunk_and_emits_nothing() {
        let mut session = cbc_session(Padding::Pkcs7);
        let out = session.ingest(b"hello").expect("ingest succeeds");
        assert_eq!(out, b"");
    }

    #[test]
    fn ingest_emits_complete_blocks_eagerly_and_buffers_residue() {
        let msg = b"exactly twenty bytes";
        assert_eq!(msg.len(), 20);
        let mut session = cbc_session(Padding::Pkcs7);
        let out = session.ingest(msg).expect("ingest succeeds");
        // The first complete block is transformed and emitted eagerly;
        // the 4-byte residue stays buffered.
        assert_eq!(out.len(), BLOCK_SIZE);
        assert_eq!(out, reference_cbc_encrypt(&msg[..BLOCK_SIZE]));
    }

    #[test]
    fn close_out_applies_pkcs7_padding() {
        let msg = b"a twenty-byte thing!";
        assert_eq!(msg.len(), 20);
        let mut session = cbc_session(Padding::Pkcs7);
        let mut out = session.ingest(msg).expect("ingest succeeds");
        out.extend(session.close_out(b"").expect("close_out succeeds"));
        assert_eq!(out, reference_cbc_encrypt(&reference_pkcs7(msg)));
    }

    #[test]
    fn close_out_applies_ansix923_padding() {
        let msg = b"a twenty-byte thing!";
        let mut padded = msg.to_vec();
        padded.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12]);

        let mut session = cbc_session(Padding::AnsiX923);
        let out = session.close_out(msg).expect("close_out succeeds");
        assert_eq!(out, reference_cbc_encrypt(&padded));
    }

    #[test]
    fn close_out_applies_iso7816_padding() {
        let msg = b"a twenty-byte thing!";
        let mut padded = msg.to_vec();
        padded.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut session = cbc_session(Padding::Iso7816);
        let out = session.close_out(msg).expect("close_out succeeds");
        assert_eq!(out, reference_cbc_encrypt(&padded));
    }

    #[test]
    fn close_out_applies_zeros_padding_to_unaligned_tail() {
        let msg = b"a twenty-byte thing!";
        let mut padded = msg.to_vec();
        padded.resize(2 * BLOCK_SIZE, 0);

        let mut session = cbc_session(Padding::Zeros);
        let out = session.close_out(msg).expect("close_out succeeds");
        assert_eq!(out, reference_cbc_encrypt(&padded));
    }

    #[test]
    fn close_out_zeros_padding_adds_no_block_when_aligned() {
        let msg = [0x5Au8; 2 * BLOCK_SIZE];
        let mut session = cbc_session(Padding::Zeros);
        let out = session.close_out(&msg).expect("close_out succeeds");
        assert_eq!(out, reference_cbc_encrypt(&msg));
    }

    #[test]
    fn close_out_none_padding_accepts_aligned_total() {
        let msg = [0xC3u8; 3 * BLOCK_SIZE];
        let mut session = cbc_session(Padding::None);
        let out = session.close_out(&msg).expect("aligned total is valid");
        assert_eq!(out, reference_cbc_encrypt(&msg));
    }

    #[test]
    fn close_out_none_padding_rejects_unaligned_total_with_length() {
        let mut session = cbc_session(Padding::None);
        // Alignment is checked once, against the *total* accumulated
        // length (21), never per-chunk (13 and 8 are both unaligned).
        session.ingest(&[0u8; 13]).expect("chunks may be unaligned");
        let err = session.close_out(&[0u8; 8]).expect_err("21 % 16 != 0");
        assert_eq!(err, EngineError::UnalignedLength { total: 21 });
        assert_eq!(
            err.to_string(),
            "data length (21) is not a multiple of the block size (16)"
        );
    }

    #[test]
    fn empty_message_block_paddings_emit_exactly_one_padding_block() {
        for padding in [Padding::Pkcs7, Padding::AnsiX923, Padding::Iso7816] {
            let mut session = cbc_session(padding);
            let out = session.close_out(b"").expect("close_out succeeds");
            assert_eq!(out.len(), BLOCK_SIZE, "{padding:?}");
        }
        // Pin the PKCS7 case byte-exactly: a full block of 0x10.
        let mut session = cbc_session(Padding::Pkcs7);
        let out = session.close_out(b"").expect("close_out succeeds");
        assert_eq!(out, reference_cbc_encrypt(&[0x10u8; BLOCK_SIZE]));
    }

    #[test]
    fn empty_message_zeros_and_none_paddings_emit_nothing() {
        for padding in [Padding::Zeros, Padding::None] {
            let mut session = cbc_session(padding);
            let out = session.close_out(b"").expect("close_out succeeds");
            assert_eq!(out, b"", "{padding:?}");
        }
    }

    #[test]
    fn ingest_after_close_out_is_rejected() {
        let mut session = cbc_session(Padding::Pkcs7);
        session.close_out(b"data").expect("close_out succeeds");
        let err = session.ingest(b"more").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
        assert_eq!(err.to_string(), "session is already finalized");
    }

    #[test]
    fn close_out_after_close_out_is_rejected() {
        let mut session = cbc_session(Padding::Pkcs7);
        session.close_out(b"data").expect("close_out succeeds");
        let err = session.close_out(b"").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
    }

    #[test]
    fn failed_close_out_still_consumes_the_session() {
        let mut session = cbc_session(Padding::None);
        session.close_out(b"unaligned").expect_err("9 % 16 != 0");
        let err = session.ingest(b"more").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
    }

    #[test]
    fn cbc_chaining_state_carries_across_ingest_calls() {
        let msg = [0xA5u8; 2 * BLOCK_SIZE];
        let mut session = cbc_session(Padding::Pkcs7);
        let mut out = session.ingest(&msg[..BLOCK_SIZE]).expect("first chunk");
        out.extend(session.ingest(&msg[BLOCK_SIZE..]).expect("second chunk"));
        assert_eq!(out, reference_cbc_encrypt(&msg));
    }

    // ---- Slice 4: decrypt ----

    /// `close_out(data)` in one call, for either direction — the
    /// one-shot case of `run_partition`.
    fn one_shot(mut session: Session, data: &[u8]) -> Vec<u8> {
        session
            .close_out(data)
            .expect("close_out succeeds on well-formed input")
    }

    #[test]
    fn cbc_decrypt_round_trips_through_encrypt_session_for_every_padding() {
        let msg = b"a twenty-byte thing!"; // 20 bytes, unaligned
        for padding in [
            Padding::Pkcs7,
            Padding::AnsiX923,
            Padding::Iso7816,
            Padding::Zeros,
        ] {
            let ciphertext = one_shot(cbc_session(padding), msg);
            let plaintext = one_shot(cbc_decrypt_session(padding), &ciphertext);
            assert_eq!(plaintext, msg, "{padding:?}");
        }

        // `None` requires an already block-aligned message.
        let aligned = [0x11u8; 2 * BLOCK_SIZE];
        let ciphertext = one_shot(cbc_session(Padding::None), &aligned);
        let plaintext = one_shot(cbc_decrypt_session(Padding::None), &ciphertext);
        assert_eq!(plaintext, aligned);
    }

    #[test]
    fn ecb_decrypt_round_trips_through_encrypt_session_for_every_padding() {
        let msg = b"a twenty-byte thing!";
        for padding in [
            Padding::Pkcs7,
            Padding::AnsiX923,
            Padding::Iso7816,
            Padding::Zeros,
        ] {
            let ciphertext = one_shot(ecb_session(padding), msg);
            let plaintext = one_shot(ecb_decrypt_session(padding), &ciphertext);
            assert_eq!(plaintext, msg, "{padding:?}");
        }

        let aligned = [0x22u8; 2 * BLOCK_SIZE];
        let ciphertext = one_shot(ecb_session(Padding::None), &aligned);
        let plaintext = one_shot(ecb_decrypt_session(Padding::None), &ciphertext);
        assert_eq!(plaintext, aligned);
    }

    #[test]
    fn holdback_ingest_of_exactly_n_blocks_emits_n_minus_1() {
        let msg: Vec<u8> = (0u8..64).collect(); // 4 aligned blocks
        let ciphertext = reference_cbc_encrypt(&msg);
        assert_eq!(ciphertext.len(), 4 * BLOCK_SIZE);

        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        let out = session
            .ingest(&ciphertext)
            .expect("ingest of 4 aligned blocks succeeds");
        // 4 blocks in, 3 blocks out — the 4th (which may carry padding)
        // stays held until close_out.
        assert_eq!(out.len(), 3 * BLOCK_SIZE);
        assert_eq!(out, reference_cbc_decrypt(&ciphertext[..3 * BLOCK_SIZE]));
    }

    #[test]
    fn holdback_single_block_ciphertext_emits_nothing_from_ingest() {
        // PKCS7-pad an empty message: exactly one full padding block.
        let ciphertext = one_shot(cbc_session(Padding::Pkcs7), b"");
        assert_eq!(ciphertext.len(), BLOCK_SIZE);

        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        let from_ingest = session.ingest(&ciphertext).expect("ingest succeeds");
        assert_eq!(from_ingest, b"");

        let from_close_out = session.close_out(b"").expect("close_out succeeds");
        assert_eq!(from_close_out, b"");
    }

    #[test]
    fn holdback_releases_previously_held_block_when_more_ciphertext_arrives() {
        // 33 bytes: pkcs7-pads to exactly 3 blocks, so the final block
        // carries real padding — round-tripping it exercises unpad, not
        // just raw block decryption.
        let msg: Vec<u8> = (0u8..33).collect();
        let ciphertext = one_shot(cbc_session(Padding::Pkcs7), &msg);
        assert_eq!(ciphertext.len(), 3 * BLOCK_SIZE);

        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        // First block: held, nothing emitted yet.
        let out1 = session
            .ingest(&ciphertext[..BLOCK_SIZE])
            .expect("first block");
        assert_eq!(out1, b"", "the first decrypted block stays held");

        // Second block arrives: the first block is released, the second
        // becomes the new held block.
        let out2 = session
            .ingest(&ciphertext[BLOCK_SIZE..2 * BLOCK_SIZE])
            .expect("second block");
        assert_eq!(
            out2.len(),
            BLOCK_SIZE,
            "the held block is released once a successor arrives"
        );

        // Close out with the third block: the second block is released
        // as-is, the third is unpadded and appended.
        let out3 = session
            .close_out(&ciphertext[2 * BLOCK_SIZE..])
            .expect("close_out");

        let mut plaintext = out1;
        plaintext.extend(out2);
        plaintext.extend(out3);
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn unpad_pkcs7_rejects_wrong_padding_bytes() {
        let mut block = [0x07u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 1] = 4; // claims 4 bytes of padding
        block[BLOCK_SIZE - 2] = 3; // but this one doesn't match
        assert_eq!(unpad_pkcs7(&block), Err(EngineError::DecryptionFailed));
    }

    #[test]
    fn unpad_pkcs7_rejects_out_of_range_length_byte() {
        for n in [0u8, 17, 255] {
            let mut block = [1u8; BLOCK_SIZE];
            block[BLOCK_SIZE - 1] = n;
            assert_eq!(
                unpad_pkcs7(&block),
                Err(EngineError::DecryptionFailed),
                "n={n}"
            );
        }
    }

    #[test]
    fn unpad_pkcs7_accepts_well_formed_padding() {
        let mut block = [0xABu8; BLOCK_SIZE];
        block[BLOCK_SIZE - 3..].fill(3);
        assert_eq!(unpad_pkcs7(&block), Ok(&block[..BLOCK_SIZE - 3]));
    }

    #[test]
    fn unpad_ansix923_rejects_nonzero_filler_byte() {
        let mut block = [0u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 1] = 5; // 5 bytes of padding
        block[BLOCK_SIZE - 3] = 0x01; // should be zero
        assert_eq!(unpad_ansix923(&block), Err(EngineError::DecryptionFailed));
    }

    #[test]
    fn unpad_ansix923_accepts_well_formed_padding() {
        let mut block = [0x99u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 4..BLOCK_SIZE - 1].fill(0);
        block[BLOCK_SIZE - 1] = 4;
        assert_eq!(unpad_ansix923(&block), Ok(&block[..BLOCK_SIZE - 4]));
    }

    #[test]
    fn unpad_iso7816_rejects_missing_marker() {
        let block = [0u8; BLOCK_SIZE]; // all zero: no 0x80 marker anywhere
        assert_eq!(unpad_iso7816(&block), Err(EngineError::DecryptionFailed));
    }

    #[test]
    fn unpad_iso7816_rejects_nonzero_byte_before_marker_is_found() {
        let mut block = [0u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 1] = 0x01; // neither 0x80 nor 0x00
        block[BLOCK_SIZE - 5] = 0x80; // a marker exists, but scanning
                                      // from the end hits the bad byte first
        assert_eq!(unpad_iso7816(&block), Err(EngineError::DecryptionFailed));
    }

    #[test]
    fn unpad_iso7816_accepts_well_formed_padding() {
        let mut block = [0x77u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 5] = 0x80;
        block[BLOCK_SIZE - 4..].fill(0);
        assert_eq!(unpad_iso7816(&block), Ok(&block[..BLOCK_SIZE - 5]));
    }

    #[test]
    fn unpad_iso7816_accepts_marker_as_final_byte() {
        // n = 1: the marker itself is the entire padding.
        let mut block = [0x33u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 1] = 0x80;
        assert_eq!(unpad_iso7816(&block), Ok(&block[..BLOCK_SIZE - 1]));
    }

    #[test]
    fn unpad_zeros_strips_trailing_zero_run_of_final_block_only() {
        let mut block = [0x44u8; BLOCK_SIZE];
        block[BLOCK_SIZE - 6..].fill(0);
        assert_eq!(unpad_zeros(&block), &block[..BLOCK_SIZE - 6]);
    }

    #[test]
    fn unpad_zeros_of_all_zero_block_yields_empty_slice() {
        let block = [0u8; BLOCK_SIZE];
        assert_eq!(unpad_zeros(&block), b"");
    }

    #[test]
    fn zeros_unpad_is_lossy_when_genuine_zero_run_straddles_the_final_block() {
        // Bytes 14..18 are a genuine (non-padding) run of zeros that
        // straddles the block boundary at 16: two zero bytes end block 1,
        // two more start what becomes the held-back block 2.
        let mut msg = vec![0xEEu8; 14];
        msg.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]); // 18 bytes total
        assert_eq!(msg.len(), 18);

        let ciphertext = one_shot(cbc_session(Padding::Zeros), &msg);
        assert_eq!(ciphertext.len(), 2 * BLOCK_SIZE); // 18 -> padded to 32

        let plaintext = one_shot(cbc_decrypt_session(Padding::Zeros), &ciphertext);
        // The two genuine zero bytes inside block 1 (indices 14, 15)
        // survive untouched; the two that fell into the held-back block 2
        // are indistinguishable from padding and are stripped along with
        // it — the RFC's documented "zeros" ambiguity, pinned exactly.
        assert_eq!(plaintext, &msg[..BLOCK_SIZE]);
        assert_ne!(
            plaintext, msg,
            "the trailing real zeros are lost, by design"
        );
    }

    #[test]
    fn cbc_decrypt_none_padding_rejects_unaligned_total_as_value_error() {
        let mut session = cbc_decrypt_session(Padding::None);
        session.ingest(&[0u8; 13]).expect("chunks may be unaligned");
        let err = session.close_out(&[0u8; 8]).expect_err("21 % 16 != 0");
        assert_eq!(err, EngineError::UnalignedLength { total: 21 });
    }

    #[test]
    fn cbc_decrypt_padded_rejects_unaligned_total_as_decryption_error() {
        // A padded scheme cannot distinguish "not really ciphertext" from
        // "corrupted ciphertext" — both collapse onto the single
        // DecryptionError channel, never the caller-usage ValueError.
        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        session.ingest(&[0u8; 13]).expect("chunks may be unaligned");
        let err = session.close_out(&[0u8; 8]).expect_err("21 % 16 != 0");
        assert_eq!(err, EngineError::DecryptionFailed);
        assert_eq!(
            err.to_string(),
            "decryption failed: invalid or corrupted ciphertext"
        );
    }

    #[test]
    fn decrypt_none_padding_of_empty_ciphertext_is_empty_plaintext() {
        let mut session = cbc_decrypt_session(Padding::None);
        let out = session.close_out(b"").expect("b\"\" is a valid total");
        assert_eq!(out, b"");
    }

    #[test]
    fn decrypt_padded_empty_ciphertext_is_decryption_error_for_every_scheme() {
        for padding in [
            Padding::Pkcs7,
            Padding::AnsiX923,
            Padding::Iso7816,
            Padding::Zeros,
        ] {
            let mut session = cbc_decrypt_session(padding);
            let err = session
                .close_out(b"")
                .expect_err("empty ciphertext is shorter than one block");
            assert_eq!(err, EngineError::DecryptionFailed, "{padding:?}");
        }
    }

    #[test]
    fn chunking_invariance_cbc_decrypt_matches_one_shot() {
        let msg: Vec<u8> = (0u8..40).collect();
        let ciphertext = one_shot(cbc_session(Padding::Pkcs7), &msg);
        let one_shot = run_partition(cbc_decrypt_session(Padding::Pkcs7), &ciphertext, &[48]);
        assert_eq!(one_shot, msg);

        let patterns: &[&[usize]] = &[
            &[1; 48],
            &[15, 1, 17, 7, 8],
            &[16, 16, 16],
            &[5, 0, 11, 7, 17, 8],
            &[47, 1],
            &[48],
        ];
        for sizes in patterns {
            let out = run_partition(cbc_decrypt_session(Padding::Pkcs7), &ciphertext, sizes);
            assert_eq!(out, one_shot, "partition {sizes:?}");
        }
    }

    #[test]
    fn chunking_invariance_ecb_decrypt_matches_one_shot() {
        let msg: Vec<u8> = (100u8..140).collect();
        let ciphertext = one_shot(ecb_session(Padding::Pkcs7), &msg);
        let one_shot = run_partition(ecb_decrypt_session(Padding::Pkcs7), &ciphertext, &[48]);
        assert_eq!(one_shot, msg);

        let patterns: &[&[usize]] = &[&[1; 48], &[15, 1, 17, 7, 8], &[16, 16, 16], &[47, 1]];
        for sizes in patterns {
            let out = run_partition(ecb_decrypt_session(Padding::Pkcs7), &ciphertext, sizes);
            assert_eq!(out, one_shot, "partition {sizes:?}");
        }
    }

    #[test]
    fn decrypt_ingest_after_close_out_is_rejected() {
        let ciphertext = one_shot(cbc_session(Padding::Pkcs7), b"data");
        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        session.close_out(&ciphertext).expect("close_out succeeds");
        let err = session.ingest(b"more").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
    }

    #[test]
    fn decrypt_close_out_after_close_out_is_rejected() {
        let ciphertext = one_shot(cbc_session(Padding::Pkcs7), b"data");
        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        session.close_out(&ciphertext).expect("close_out succeeds");
        let err = session.close_out(b"").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
    }

    #[test]
    fn failed_decrypt_close_out_still_consumes_the_session() {
        let mut session = cbc_decrypt_session(Padding::Pkcs7);
        session
            .close_out(&[0u8; 9])
            .expect_err("9 bytes is shorter than one block");
        let err = session.ingest(b"more").expect_err("session is consumed");
        assert_eq!(err, EngineError::SessionFinalized);
    }

    // ---- Slice 5: keystream (CTR/OFB) + CFB live feedback state ----

    fn cfb_encrypt_session() -> Session {
        Session::cfb_encryptor(cipher(), &IV)
    }

    fn cfb_decrypt_session() -> Session {
        Session::cfb_decryptor(cipher(), &IV)
    }

    fn ctr_encrypt_session() -> Session {
        Session::ctr_encryptor(cipher(), &IV)
    }

    fn ctr_decrypt_session() -> Session {
        Session::ctr_decryptor(cipher(), &IV)
    }

    fn ofb_encrypt_session() -> Session {
        Session::ofb_encryptor(cipher(), &IV)
    }

    fn ofb_decrypt_session() -> Session {
        Session::ofb_decryptor(cipher(), &IV)
    }

    /// Independent CFB reference (full-block feedback): keystream for a
    /// block is `encrypt(register)`; `register` starts as `iv` and becomes
    /// the block's own *ciphertext* once a full block is produced. A
    /// non-block-aligned tail uses a truncated keystream block and never
    /// advances the register further (there is no next block) — the same
    /// discipline [`Transform::apply_partial_feedback_block`] implements.
    fn reference_cfb_encrypt(key: &[u8], iv: [u8; BLOCK_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Twofish::new_from_slice(key).expect("valid key");
        let mut register = iv;
        let mut out = Vec::with_capacity(plaintext.len());
        for chunk in plaintext.chunks(BLOCK_SIZE) {
            let mut ks = Block::<Twofish>::clone_from_slice(&register);
            cipher.encrypt_block(&mut ks);
            let mut block = [0u8; BLOCK_SIZE];
            for (b, (&p, &k)) in block.iter_mut().zip(chunk.iter().zip(ks.iter())) {
                *b = p ^ k;
            }
            out.extend_from_slice(&block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                register = block;
            }
        }
        out
    }

    /// Independent CFB decrypt reference: symmetric to
    /// [`reference_cfb_encrypt`], except the register becomes the block's
    /// own *ciphertext* input rather than the computed output.
    fn reference_cfb_decrypt(key: &[u8], iv: [u8; BLOCK_SIZE], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = Twofish::new_from_slice(key).expect("valid key");
        let mut register = iv;
        let mut out = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let mut ks = Block::<Twofish>::clone_from_slice(&register);
            cipher.encrypt_block(&mut ks);
            let mut block = [0u8; BLOCK_SIZE];
            for (b, (&c, &k)) in block.iter_mut().zip(chunk.iter().zip(ks.iter())) {
                *b = c ^ k;
            }
            out.extend_from_slice(&block[..chunk.len()]);
            if chunk.len() == BLOCK_SIZE {
                register.copy_from_slice(chunk);
            }
        }
        out
    }

    /// Independent CTR reference: the 16-byte IV is a single big-endian
    /// u128 initial counter block, incremented by one per block — no raw
    /// crate involved, mirroring [`Transform::Ctr`]'s documented contract.
    fn reference_ctr(key: &[u8], iv: [u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
        let cipher = Twofish::new_from_slice(key).expect("valid key");
        let mut counter = u128::from_be_bytes(iv);
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(BLOCK_SIZE) {
            let mut ks = Block::<Twofish>::clone_from_slice(&counter.to_be_bytes());
            cipher.encrypt_block(&mut ks);
            for (&b, &k) in chunk.iter().zip(ks.iter()) {
                out.push(b ^ k);
            }
            counter = counter.wrapping_add(1);
        }
        out
    }

    /// Independent OFB reference: the register is repeatedly re-encrypted
    /// (a plaintext/ciphertext-independent keystream chain), unlike CFB's
    /// ciphertext-derived register.
    fn reference_ofb(key: &[u8], iv: [u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
        let cipher = Twofish::new_from_slice(key).expect("valid key");
        let mut register = iv;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(BLOCK_SIZE) {
            let mut ks = Block::<Twofish>::clone_from_slice(&register);
            cipher.encrypt_block(&mut ks);
            register.copy_from_slice(&ks);
            for (&b, &k) in chunk.iter().zip(ks.iter()) {
                out.push(b ^ k);
            }
        }
        out
    }

    #[test]
    fn cfb_round_trips_through_encrypt_session_for_every_length_including_empty() {
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 63] {
            let msg: Vec<u8> = (0u8..len as u8).map(|b| b.wrapping_mul(7)).collect();
            let ciphertext = one_shot(cfb_encrypt_session(), &msg);
            assert_eq!(
                ciphertext,
                reference_cfb_encrypt(&KEY, IV, &msg),
                "len={len}"
            );
            assert_eq!(ciphertext.len(), len, "CFB never pads: len={len}");

            let plaintext = one_shot(cfb_decrypt_session(), &ciphertext);
            assert_eq!(plaintext, msg, "len={len}");
        }
    }

    #[test]
    fn ctr_round_trips_and_is_its_own_inverse() {
        let msg: Vec<u8> = (0u8..77).collect();
        let ciphertext = one_shot(ctr_encrypt_session(), &msg);
        assert_eq!(ciphertext, reference_ctr(&KEY, IV, &msg));
        assert_eq!(ciphertext.len(), msg.len(), "CTR never pads");

        let plaintext = one_shot(ctr_decrypt_session(), &ciphertext);
        assert_eq!(plaintext, msg);
        // CTR is its own inverse: applying the reference keystream to the
        // ciphertext recovers the plaintext without a separate decrypt path.
        assert_eq!(reference_ctr(&KEY, IV, &ciphertext), msg);
    }

    #[test]
    fn ofb_round_trips_and_is_its_own_inverse() {
        let msg: Vec<u8> = (0u8..77).collect();
        let ciphertext = one_shot(ofb_encrypt_session(), &msg);
        assert_eq!(ciphertext, reference_ofb(&KEY, IV, &msg));
        assert_eq!(ciphertext.len(), msg.len(), "OFB never pads");

        let plaintext = one_shot(ofb_decrypt_session(), &ciphertext);
        assert_eq!(plaintext, msg);
        assert_eq!(reference_ofb(&KEY, IV, &ciphertext), msg);
    }

    /// Chunking patterns shared by the three stream-mode invariance tests
    /// below: byte-at-a-time, ragged sizes, chunks that include zero-length
    /// entries (mid-stream and as the trailing `close_out` chunk), and the
    /// one-shot case itself. Every pattern sums to `len`.
    fn stream_chunk_patterns(len: usize) -> Vec<Vec<usize>> {
        assert_eq!(
            len, 50,
            "patterns below are hand-sized for a 50-byte message"
        );
        vec![
            vec![1; 50],
            vec![0, 1, 0, 15, 0, 1, 17, 0, 7, 9],
            vec![16, 16, 16, 2],
            vec![5, 0, 11, 7, 17, 10],
            vec![49, 1],
            vec![50],
            vec![50, 0],
        ]
    }

    #[test]
    fn chunking_invariance_cfb_encrypt_matches_one_shot_and_oracle() {
        let msg: Vec<u8> = (0u8..50).collect();
        let one_shot_ct = one_shot(cfb_encrypt_session(), &msg);
        assert_eq!(one_shot_ct, reference_cfb_encrypt(&KEY, IV, &msg));

        for sizes in stream_chunk_patterns(msg.len()) {
            let out = run_partition(cfb_encrypt_session(), &msg, &sizes);
            assert_eq!(out, one_shot_ct, "partition {sizes:?}");
        }
    }

    #[test]
    fn chunking_invariance_cfb_decrypt_matches_one_shot_and_oracle() {
        let msg: Vec<u8> = (0u8..50).collect();
        let ciphertext = one_shot(cfb_encrypt_session(), &msg);
        let one_shot_pt = one_shot(cfb_decrypt_session(), &ciphertext);
        assert_eq!(one_shot_pt, msg);
        assert_eq!(one_shot_pt, reference_cfb_decrypt(&KEY, IV, &ciphertext));

        for sizes in stream_chunk_patterns(ciphertext.len()) {
            let out = run_partition(cfb_decrypt_session(), &ciphertext, &sizes);
            assert_eq!(out, msg, "partition {sizes:?}");
        }
    }

    #[test]
    fn chunking_invariance_ctr_matches_one_shot_and_oracle() {
        let msg: Vec<u8> = (0u8..50).collect();
        let one_shot_ct = one_shot(ctr_encrypt_session(), &msg);
        assert_eq!(one_shot_ct, reference_ctr(&KEY, IV, &msg));

        for sizes in stream_chunk_patterns(msg.len()) {
            let out = run_partition(ctr_encrypt_session(), &msg, &sizes);
            assert_eq!(out, one_shot_ct, "partition {sizes:?}");
        }
        for sizes in stream_chunk_patterns(one_shot_ct.len()) {
            let out = run_partition(ctr_decrypt_session(), &one_shot_ct, &sizes);
            assert_eq!(out, msg, "decrypt partition {sizes:?}");
        }
    }

    #[test]
    fn chunking_invariance_ofb_matches_one_shot_and_oracle() {
        let msg: Vec<u8> = (0u8..50).collect();
        let one_shot_ct = one_shot(ofb_encrypt_session(), &msg);
        assert_eq!(one_shot_ct, reference_ofb(&KEY, IV, &msg));

        for sizes in stream_chunk_patterns(msg.len()) {
            let out = run_partition(ofb_encrypt_session(), &msg, &sizes);
            assert_eq!(out, one_shot_ct, "partition {sizes:?}");
        }
        for sizes in stream_chunk_patterns(one_shot_ct.len()) {
            let out = run_partition(ofb_decrypt_session(), &one_shot_ct, &sizes);
            assert_eq!(out, msg, "decrypt partition {sizes:?}");
        }
    }

    #[test]
    fn ctr_and_ofb_ingest_are_immediately_byte_granular_unlike_cfb() {
        // CTR/OFB: StreamCipherCoreWrapper buffers internally, but every
        // ingested byte is transformed and returned on the same call.
        let mut ctr = ctr_encrypt_session();
        assert_eq!(ctr.ingest(b"A").expect("ingest succeeds").len(), 1);

        let mut ofb = ofb_encrypt_session();
        assert_eq!(ofb.ingest(b"A").expect("ingest succeeds").len(), 1);

        // CFB: the engine's own `pending` buffer withholds sub-block
        // residue, same discipline as CBC/ECB, until a full block or
        // close_out resolves it.
        let mut cfb = cfb_encrypt_session();
        assert_eq!(
            cfb.ingest(b"A").expect("ingest succeeds").len(),
            0,
            "CFB buffers sub-block residue like CBC/ECB"
        );
    }

    #[test]
    fn empty_message_stream_and_feedback_modes_produce_nothing() {
        let sessions = [
            cfb_encrypt_session(),
            cfb_decrypt_session(),
            ctr_encrypt_session(),
            ctr_decrypt_session(),
            ofb_encrypt_session(),
            ofb_decrypt_session(),
        ];
        for session in sessions {
            let out = one_shot(session, b"");
            assert_eq!(out, b"");
        }
    }

    #[test]
    fn stream_and_feedback_sessions_reject_ingest_after_close_out() {
        let sessions = [
            cfb_encrypt_session(),
            ctr_encrypt_session(),
            ofb_encrypt_session(),
        ];
        for mut session in sessions {
            session.close_out(b"data").expect("close_out succeeds");
            let err = session.ingest(b"more").expect_err("session is consumed");
            assert_eq!(err, EngineError::SessionFinalized);
        }
    }

    #[test]
    fn stream_and_feedback_sessions_reject_close_out_after_close_out() {
        let sessions = [
            cfb_decrypt_session(),
            ctr_decrypt_session(),
            ofb_decrypt_session(),
        ];
        for mut session in sessions {
            session.close_out(b"data").expect("close_out succeeds");
            let err = session.close_out(b"").expect_err("session is consumed");
            assert_eq!(err, EngineError::SessionFinalized);
        }
    }

    #[test]
    fn cfb_chaining_state_carries_across_ingest_calls() {
        let msg = [0xA5u8; 2 * BLOCK_SIZE];
        let mut session = cfb_encrypt_session();
        let mut out = session.ingest(&msg[..BLOCK_SIZE]).expect("first chunk");
        out.extend(session.ingest(&msg[BLOCK_SIZE..]).expect("second chunk"));
        assert_eq!(out, reference_cfb_encrypt(&KEY, IV, &msg));
    }

    #[test]
    fn cfb_structural_fix_matches_pinned_vector_regardless_of_chunking() {
        // Same key/iv/plaintext as tests/test_characterization.py's
        // TestCFBStreamingFeedbackRegisterBug (the old-API bug pins), and
        // the same one-shot ciphertext pinned there as the known-good
        // continuous CFB stream. The old engine's streaming with 5-byte
        // chunks produced a frozen, wrong stream ("0f5d5861e7" repeated 8x
        // -- keystream reuse); with 20-byte chunks, a different but still
        // wrong stream (misaligned feedback window). The new engine must
        // reproduce the one true continuous stream under every chunking --
        // the structural proof the bug class cannot recur.
        let key = b"0123456789abcdef";
        let iv = *b"fedcba9876543210";
        let plaintext = [b'A'; 40];
        let expected = hex::decode(
            "0f5d5861e787486c9ca9fd328e9d401373f72681c1aedfb6dc3fb166417c7de6ab497ee6ec0b9714",
        )
        .expect("valid hex");
        let old_buggy_frozen_output = "0f5d5861e7".repeat(8);

        let make_cipher = || Twofish::new_from_slice(key).expect("16-byte key is valid");

        let one_shot_ct = one_shot(Session::cfb_encryptor(make_cipher(), &iv), &plaintext);
        assert_eq!(one_shot_ct, expected);
        assert_eq!(reference_cfb_encrypt(key, iv, &plaintext), expected);

        for chunk_size in [1usize, 3, 5, 20] {
            let mut sizes = vec![chunk_size; plaintext.len() / chunk_size];
            let remainder = plaintext.len() % chunk_size;
            if remainder != 0 {
                sizes.push(remainder);
            }
            let session = Session::cfb_encryptor(make_cipher(), &iv);
            let out = run_partition(session, &plaintext, &sizes);
            assert_eq!(out, expected, "chunk_size={chunk_size}");
            assert_ne!(
                hex::encode(&out),
                old_buggy_frozen_output,
                "must not reproduce the old frozen-register output, chunk_size={chunk_size}"
            );

            let dsession = Session::cfb_decryptor(make_cipher(), &iv);
            let recovered = run_partition(dsession, &expected, &sizes);
            assert_eq!(recovered, plaintext, "decrypt chunk_size={chunk_size}");
        }
    }
}
