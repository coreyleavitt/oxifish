//! In-repo XTS-mode engine (RFC 0003 slice 3).
//!
//! IEEE 1619-2007 XTS-AES generalizes cleanly to any 16-byte-block cipher —
//! this module implements that generalization directly against the `cipher`
//! 0.5 traits rather than depending on the unmaintained `xts-mode` crate
//! (see the RFC's Dependency Strategy). [`XtsCipher<C>`] is generic over any
//! `C: BlockCipherEncrypt + BlockCipherDecrypt` with a 16-byte block, which
//! is what lets the cargo test suite below instantiate it with `aes` and
//! pin it against the official IEEE P1619/D16 Annex B known-answer vectors
//! (Twofish has no published XTS vectors of its own — see the RFC's Testing
//! Strategy). The production instantiation (`XtsCipher<twofish::Twofish>`)
//! is wired up to Python in slice 4.
//!
//! **Not a [`crate::engine::Session`].** XTS is one-shot and per-data-unit:
//! there is no IV, no padding, and no streaming state machine to thread
//! through — every data unit is encrypted/decrypted independently given its
//! tweak. `src/engine.rs` is untouched by this module (see the RFC's
//! "XTS lives in a sibling module" note).
//!
//! # Algorithm
//!
//! Each data unit is encrypted under two independently scheduled instances
//! of the same block cipher: `data_cipher` (IEEE's "Key1") transforms the
//! plaintext/ciphertext blocks; `tweak_cipher` ("Key2") encrypts the
//! data-unit's tweak value once to produce the initial per-block tweak
//! `T_0`. Successive per-block tweaks `T_j` are derived from `T_0` by
//! repeated multiplication by the primitive element `α` of GF(2¹²⁸) (the
//! field defined by `x¹²⁸ + x⁷ + x² + x + 1`), computed with
//! [`gf128_double`]. Each block is then XEX-transformed:
//! `C_j = E(Key1, P_j ⊕ T_j) ⊕ T_j` (encrypt) or the corresponding decrypt.
//!
//! **Ciphertext stealing (IEEE 1619 §5.3.2/§5.4.2).** When a data unit's
//! length is not a multiple of 16 bytes, the last full block `P_{m-1}` and
//! the trailing partial block `P_m` (`tail_len` bytes) are handled
//! together. Encrypt: `CC = XEX(P_{m-1}, T_{m-1})` is computed as normal,
//! but only its first `tail_len` bytes are emitted — as the data unit's
//! *final, short* ciphertext block `C_m`. The stolen remainder of `CC` is
//! folded into `PP = P_m ‖ CC[tail_len..]`, which is XEX-encrypted under
//! the **next** tweak `T_m` to become the full ciphertext block `C_{m-1}`,
//! emitted *before* `C_m`. This is the "next-to-last/last tweak swap":
//! the next-to-last ciphertext block carries the doubled tweak `T_m`
//! while the last (short) one derives from `T_{m-1}`. Decrypt reverses
//! it: the full block is XEX-decrypted under `T_m` first, recovering the
//! tail plaintext and the stolen bytes of `CC`; `CC` is then reassembled
//! and XEX-decrypted under `T_{m-1}` to recover `P_{m-1}`.
//! [`XtsCipher::encrypt_data_unit`] and [`XtsCipher::decrypt_data_unit`]
//! implement exactly this.

use core::fmt;

use cipher::{consts::U16, Block, BlockCipherDecrypt, BlockCipherEncrypt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::engine::BLOCK_SIZE;

/// IEEE 1619-2007's data-unit upper bound: at most 2²⁰ 128-bit blocks
/// (16 MiB). Real formats (VeraCrypt's 512-byte sectors, dm-crypt's
/// sector-sized units) sit far below this; enforcing it here caps the
/// mode's security-bound erosion, per the RFC's Proposed Interface §2.
pub(crate) const MAX_DATA_UNIT_BYTES: usize = (1usize << 20) * BLOCK_SIZE;

/// Minimum data unit: one full block. XTS requires at least 128 bits of
/// input; ciphertext stealing has nothing to steal from with less.
pub(crate) const MIN_DATA_UNIT_BYTES: usize = BLOCK_SIZE;

/// Engine-level XTS failures. The PyO3 facade (slice 4) maps these onto the
/// RFC's normative error catalog.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum XtsError {
    /// `encrypt_data_unit`/`decrypt_data_unit` called with a data unit
    /// shorter than [`MIN_DATA_UNIT_BYTES`] or longer than
    /// [`MAX_DATA_UNIT_BYTES`]. Carries the offending length. Checked in
    /// this crate's own code before any dependency call — no
    /// dependency-internal assert is reachable from a bad length (RFC
    /// Contracts).
    InvalidLength { len: usize },
}

impl fmt::Display for XtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XtsError::InvalidLength { len } => write!(
                f,
                "XTS data unit must be {MIN_DATA_UNIT_BYTES} to {MAX_DATA_UNIT_BYTES} bytes, got {len} bytes"
            ),
        }
    }
}

impl std::error::Error for XtsError {}

/// The in-repo XTS-mode engine: owns two independently scheduled instances
/// of the same 16-byte-block cipher (`data_cipher` = IEEE's Key1,
/// `tweak_cipher` = Key2) and transforms one data unit at a time.
///
/// **Equal key schedules are accepted.** The RFC's `TwofishXTS` facade
/// (slice 4) rejects equal key halves at construction — that guard is
/// scoped to the facade, not this engine, because the official IEEE 1619
/// Vector 1 (Key1 == Key2, both all-zero) must run at this level to prove
/// the generic implementation against its known answer.
///
/// One-shot only: XTS is random-access by construction (each data unit is
/// independent of every other), so there is no streaming state to hold —
/// unlike [`crate::engine::Session`], nothing here survives between calls.
///
/// Zeroization: `C`'s own `Drop`/`ZeroizeOnDrop` impl (Twofish's and AES's
/// both zeroize their expanded key schedules) fires for `data_cipher` and
/// `tweak_cipher` when an `XtsCipher` drops — see the `ZeroizeOnDrop`
/// forwarding impl below. Owned scratch used *during* a single
/// `encrypt_data_unit`/`decrypt_data_unit` call (per-block tweaks and the
/// ciphertext-stealing intermediates) is zeroized explicitly before it goes
/// out of scope, matching `engine.rs`'s discipline for intermediate
/// plaintext/keystream copies.
pub(crate) struct XtsCipher<C> {
    data_cipher: C,
    tweak_cipher: C,
}

impl<C> XtsCipher<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + BlockCipherDecrypt<BlockSize = U16>,
{
    /// Build an engine from two already-scheduled cipher instances. Takes
    /// ownership (per-instance zeroization on drop, matching `engine.rs`'s
    /// non-ECB session constructors) rather than borrowing, since XTS has
    /// no shared-schedule ECB-style use case.
    pub(crate) fn new(data_cipher: C, tweak_cipher: C) -> Self {
        Self {
            data_cipher,
            tweak_cipher,
        }
    }

    /// Encrypt one data unit. `tweak` is the IEEE 1619 data-unit sequence
    /// number, little-endian encoded into the 128-bit tweak block *by this
    /// function* (RFC: tweak-block encoding lives in the engine, not the
    /// slice 4 facade). `len(output) == len(plaintext)` always (length
    /// preservation is a pinned property); non-block-multiple lengths are
    /// handled via ciphertext stealing (see the module docs).
    ///
    /// # Errors
    /// [`XtsError::InvalidLength`] if `plaintext.len()` is outside
    /// `MIN_DATA_UNIT_BYTES..=MAX_DATA_UNIT_BYTES`. Never panics on a bad
    /// length — this check runs before any cipher call.
    pub(crate) fn encrypt_data_unit(
        &self,
        plaintext: &[u8],
        tweak: u128,
    ) -> Result<Vec<u8>, XtsError> {
        validate_len(plaintext.len())?;
        let (full_blocks, tail_len) = block_layout(plaintext.len());
        let normal_blocks = full_blocks - usize::from(tail_len > 0);

        let mut t = Zeroizing::new(self.initial_tweak(tweak));
        let mut out = Vec::with_capacity(plaintext.len());

        for j in 0..normal_blocks {
            let mut block = read_block(plaintext, j * BLOCK_SIZE);
            self.xex_encrypt(&mut block, &t);
            out.extend_from_slice(&block);
            block.zeroize();
            gf128_double(&mut t);
        }

        if tail_len == 0 {
            return Ok(out);
        }

        // `t` has advanced exactly `normal_blocks` (= full_blocks - 1)
        // times since T_0, so it is now T_{m-1} in IEEE numbering: the
        // tweak for CC, the intermediate encryption of the last full
        // plaintext block. The final full *ciphertext* block is encrypted
        // under the next tweak T_m -- the tweak swap.
        let last_full_start = normal_blocks * BLOCK_SIZE;
        let tail_start = last_full_start + BLOCK_SIZE;

        let mut cc = read_block(plaintext, last_full_start);
        self.xex_encrypt(&mut cc, &t);

        // PP = tail plaintext ‖ the unstolen remainder of CC.
        let mut pp = [0u8; BLOCK_SIZE];
        pp[..tail_len].copy_from_slice(&plaintext[tail_start..]);
        pp[tail_len..].copy_from_slice(&cc[tail_len..]);

        gf128_double(&mut t);
        self.xex_encrypt(&mut pp, &t);

        // Ciphertext order per IEEE 1619 §5.3.2: the full block C_{m-1}
        // (PP under T_m) comes first, then the short block C_m (the
        // stolen prefix of CC, which used T_{m-1}).
        out.extend_from_slice(&pp);
        out.extend_from_slice(&cc[..tail_len]);
        pp.zeroize();
        cc.zeroize();

        Ok(out)
    }

    /// Decrypt one data unit. See [`XtsCipher::encrypt_data_unit`] for the
    /// tweak/length contract, which this mirrors exactly; the
    /// ciphertext-stealing branch performs the next-to-last/last tweak
    /// swap in reverse (see the module docs).
    ///
    /// # Errors
    /// [`XtsError::InvalidLength`] under the same conditions as
    /// [`XtsCipher::encrypt_data_unit`].
    pub(crate) fn decrypt_data_unit(
        &self,
        ciphertext: &[u8],
        tweak: u128,
    ) -> Result<Vec<u8>, XtsError> {
        validate_len(ciphertext.len())?;
        let (full_blocks, tail_len) = block_layout(ciphertext.len());
        let normal_blocks = full_blocks - usize::from(tail_len > 0);

        let mut t = Zeroizing::new(self.initial_tweak(tweak));
        let mut out = Vec::with_capacity(ciphertext.len());

        for j in 0..normal_blocks {
            let mut block = read_block(ciphertext, j * BLOCK_SIZE);
            self.xex_decrypt(&mut block, &t);
            out.extend_from_slice(&block);
            block.zeroize();
            gf128_double(&mut t);
        }

        if tail_len == 0 {
            return Ok(out);
        }

        // Ciphertext layout (IEEE 1619 §5.4.2): [normal blocks][full
        // block C_{m-1}][short block C_m of `tail_len` bytes]. `t` is
        // currently T_{m-1}. The tweak swap in reverse: C_{m-1} was
        // encrypted under T_m (the *doubled* tweak), while the short
        // block is the stolen prefix of CC, which used T_{m-1}.
        let last_full_start = normal_blocks * BLOCK_SIZE;
        let short_start = last_full_start + BLOCK_SIZE;

        let mut t_next = Zeroizing::new(*t);
        gf128_double(&mut t_next);

        let mut pp = read_block(ciphertext, last_full_start);
        self.xex_decrypt(&mut pp, &t_next);
        // PP = tail plaintext ‖ the stolen remainder of CC.

        let mut cc = [0u8; BLOCK_SIZE];
        cc[..tail_len].copy_from_slice(&ciphertext[short_start..]);
        cc[tail_len..].copy_from_slice(&pp[tail_len..]);
        self.xex_decrypt(&mut cc, &t);
        // cc is now the recovered last full plaintext block.

        out.extend_from_slice(&cc);
        out.extend_from_slice(&pp[..tail_len]);
        cc.zeroize();
        pp.zeroize();

        Ok(out)
    }

    /// `T_0`: `AES-enc(Key2, i)` in IEEE 1619's notation, where `i` is the
    /// tweak's 128-bit little-endian byte encoding (computed here, not the
    /// slice 4 facade). Doubling to `T_1, T_2, ...` is the caller's job via
    /// [`gf128_double`].
    fn initial_tweak(&self, tweak: u128) -> [u8; BLOCK_SIZE] {
        let mut t = tweak.to_le_bytes();
        encrypt_block_raw(&self.tweak_cipher, &mut t);
        t
    }

    /// One XEX-encrypt step: `block <- E(Key1, block XOR t) XOR t`.
    fn xex_encrypt(&self, block: &mut [u8; BLOCK_SIZE], t: &[u8; BLOCK_SIZE]) {
        xor_in_place(block, t);
        encrypt_block_raw(&self.data_cipher, block);
        xor_in_place(block, t);
    }

    /// One XEX-decrypt step: `block <- D(Key1, block XOR t) XOR t`.
    fn xex_decrypt(&self, block: &mut [u8; BLOCK_SIZE], t: &[u8; BLOCK_SIZE]) {
        xor_in_place(block, t);
        decrypt_block_raw(&self.data_cipher, block);
        xor_in_place(block, t);
    }
}

/// Forwards `ZeroizeOnDrop` from the underlying cipher: a marker only (the
/// trait has no methods -- see `zeroize`'s definition), honest here because
/// `XtsCipher` has no custom `Drop` of its own, so its fields are dropped
/// by the compiler's ordinary field-wise drop glue, which is exactly what
/// invokes `C`'s own zeroizing `Drop` impl for `data_cipher` and
/// `tweak_cipher`. Mirrors `twofish::Twofish`'s own
/// `impl ZeroizeOnDrop for Twofish {}`.
impl<C: ZeroizeOnDrop> ZeroizeOnDrop for XtsCipher<C> {}

/// Reject data units outside IEEE 1619's `[128 bits, 2²⁰ blocks]` range.
/// The single validation gate both [`XtsCipher::encrypt_data_unit`]/
/// [`XtsCipher::decrypt_data_unit`] call before touching either cipher --
/// no dependency-internal assert is reachable from a bad length. `pub(crate)`
/// (code-review finding L1) so `xts_py.rs` can also call it directly on the
/// caller's borrowed buffer *before* copying it into owned memory --
/// rejecting an oversized input without ever paying for the copy. The
/// engine-internal call above stays in place as defense in depth (e.g. for
/// any future non-pyo3 caller of this module), so a bad length is still
/// caught here even if a caller skipped the pre-copy check.
pub(crate) fn validate_len(len: usize) -> Result<(), XtsError> {
    if (MIN_DATA_UNIT_BYTES..=MAX_DATA_UNIT_BYTES).contains(&len) {
        Ok(())
    } else {
        Err(XtsError::InvalidLength { len })
    }
}

/// Split a validated data-unit length into `(full_blocks, tail_len)`:
/// `full_blocks` is the number of complete 16-byte blocks, including a
/// last full block that ciphertext stealing folds together with
/// `tail_len` trailing bytes (`0` when the length is exactly block-aligned).
fn block_layout(len: usize) -> (usize, usize) {
    (len / BLOCK_SIZE, len % BLOCK_SIZE)
}

/// Copy one 16-byte block out of `data` starting at `offset`. The caller
/// guarantees `offset + BLOCK_SIZE <= data.len()` (both call sites derive
/// `offset` from `block_layout`'s own arithmetic over `data.len()`).
fn read_block(data: &[u8], offset: usize) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
    block
}

/// XOR `t` into `block` in place -- the XEX construction's two XOR steps
/// share this helper.
fn xor_in_place(block: &mut [u8; BLOCK_SIZE], t: &[u8; BLOCK_SIZE]) {
    for (b, tw) in block.iter_mut().zip(t.iter()) {
        *b ^= tw;
    }
}

/// Multiply a tweak block by GF(2¹²⁸)'s primitive element `α`, in place.
/// The field is `GF(2)[x] / (x¹²⁸ + x⁷ + x² + x + 1)`, represented
/// LSB-first: `block[0]` bit 0 is the coefficient of `x⁰`, `block[15]` bit
/// 7 is the coefficient of `x¹²⁷`. Multiplying by `α` (= `x`) is a
/// whole-block left-shift-by-one-bit propagated low-byte-first, reducing
/// modulo the field polynomial by XORing `0x87` (`x⁷+x²+x+1`) into the low
/// byte whenever the shift overflows out of `x¹²⁷`.
///
/// Not tested in isolation (per the RFC's Testing Strategy) -- its
/// correctness is proven transitively by the multi-block IEEE 1619 vectors
/// below, which cannot pass with an incorrect doubling step.
fn gf128_double(block: &mut [u8; BLOCK_SIZE]) {
    let mut carry = 0u8;
    for byte in block.iter_mut() {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        block[0] ^= 0x87;
    }
}

/// Encrypt one 16-byte block in place through any `BlockCipherEncrypt`
/// implementor with a 16-byte block -- the `Block<C>`/hybrid-array
/// round-trip in one place, shared by every call site. `b` holds the XEX
/// intermediate (`P_j XOR T_j`, then the raw block-cipher output) copied
/// out of the caller's own array -- an engine-owned duplicate, scrubbed
/// before it drops, matching this module's zeroization discipline for
/// every other owned intermediate.
fn encrypt_block_raw<C: BlockCipherEncrypt<BlockSize = U16>>(
    cipher: &C,
    block: &mut [u8; BLOCK_SIZE],
) {
    let mut b = Block::<C>::from(*block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
    b.as_mut_slice().zeroize();
}

/// Decrypt one 16-byte block in place. See [`encrypt_block_raw`] re: the
/// same intermediate-zeroization discipline (here `b` holds the raw
/// block-cipher decrypt output, pre-XOR with the tweak).
fn decrypt_block_raw<C: BlockCipherDecrypt<BlockSize = U16>>(
    cipher: &C,
    block: &mut [u8; BLOCK_SIZE],
) {
    let mut b = Block::<C>::from(*block);
    cipher.decrypt_block(&mut b);
    block.copy_from_slice(&b);
    b.as_mut_slice().zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::{Aes128, Aes256};
    use cipher::KeyInit;
    use static_assertions::assert_impl_all;
    use twofish::Twofish;
    use xts_mode::{get_tweak_default, Xts128};
    use zeroize::ZeroizeOnDrop;

    // ---- Zeroization ----

    assert_impl_all!(XtsCipher<Twofish>: ZeroizeOnDrop);

    // ================================================================
    // IEEE P1619/D16 ("P1619-2007"), Annex B known-answer vectors.
    //
    // Sourced from the IEEE draft itself (fetched directly:
    // https://crossbowerbt.github.io/docs/crypto/pdf00086.pdf, Annex B)
    // and cross-checked byte-for-byte against a second, independent
    // reproduction (cryptopp's TestVectors/xts.txt, which cites the same
    // "P1619-2007, Appendix B" source and is machine-generated from the
    // IEEE reference implementation) -- both agree on every vector used
    // here. Vector 10 is additionally cross-checked against VeraCrypt's
    // own self-test table (`Tests.c`, `XTS_vectors[0]`, commented "IEEE
    // 1619 - Vector 10"), which reproduces the identical key/tweak/
    // plaintext/ciphertext bytes independently of both sources above.
    //
    // Half the annex is block-aligned and easy to mistake for the whole
    // set (RFC caution) -- vector numbers are cited in every test name.
    // Vectors 15-18 are the data units IEEE actually made non-block-
    // aligned (17/18/19/20 bytes) and are what exercises the
    // ciphertext-stealing branch; Vector 19, despite being filed under
    // the same "not a multiple of 16 bytes" Annex B heading as 15-18, is
    // itself a 512-byte (block-aligned) data unit in the source
    // document -- included here as an additional large block-aligned
    // case, not as CTS coverage.
    // ================================================================

    fn aes128(key: [u8; 16]) -> Aes128 {
        Aes128::new_from_slice(&key).expect("16-byte key is valid")
    }

    fn aes256(key: [u8; 32]) -> Aes256 {
        Aes256::new_from_slice(&key).expect("32-byte key is valid")
    }

    /// Vector 1: XTS-AES-128, 32-byte data unit, **Key1 == Key2** (both
    /// all-zero). The equal-keys case IEEE Vector 1 exercises -- this
    /// engine must accept it (the equal-halves rejection is a slice 4
    /// facade concern; see the RFC's §2 scoping and this module's docs).
    #[test]
    fn ieee1619_vector_01_xts_aes128_equal_keys_32_byte_unit() {
        let key1 = [0x00u8; 16];
        let key2 = [0x00u8; 16];
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = [0x00u8; 32];
        let ciphertext =
            hex::decode("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e")
                .unwrap();

        assert_eq!(xts.encrypt_data_unit(&plaintext, 0).unwrap(), ciphertext);
        assert_eq!(xts.decrypt_data_unit(&ciphertext, 0).unwrap(), plaintext);
    }

    /// Vector 2: XTS-AES-128, 32-byte data unit, distinct keys. The data
    /// unit sequence number is the five bytes `33 33 33 33 33`,
    /// little-endian encoded (IEEE's convention) = `0x3333333333`.
    #[test]
    fn ieee1619_vector_02_xts_aes128_32_byte_unit() {
        let key1 = [0x11u8; 16];
        let key2 = [0x22u8; 16];
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = [0x44u8; 32];
        let ciphertext =
            hex::decode("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0")
                .unwrap();
        let tweak: u128 = 0x3333333333;

        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 3: XTS-AES-128, 32-byte data unit, same tweak/plaintext as
    /// Vector 2 with a different Key1 -- pins that Key1 alone changes the
    /// ciphertext.
    #[test]
    fn ieee1619_vector_03_xts_aes128_32_byte_unit() {
        let key1: [u8; 16] = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .try_into()
            .unwrap();
        let key2 = [0x22u8; 16];
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = [0x44u8; 32];
        let ciphertext =
            hex::decode("af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89")
                .unwrap();
        let tweak: u128 = 0x3333333333;

        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 15: XTS-AES-128, 17-byte data unit -- the shortest possible
    /// ciphertext-stealing case (one full block plus one tail byte).
    #[test]
    fn ieee1619_vector_15_xts_aes128_17_byte_unit_cts() {
        let key1: [u8; 16] = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode("000102030405060708090a0b0c0d0e0f10").unwrap();
        let ciphertext = hex::decode("6c1625db4671522d3d7599601de7ca09ed").unwrap();
        let tweak: u128 = 0x123456789a;

        assert_eq!(plaintext.len(), 17);
        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 16: XTS-AES-128, 18-byte data unit (ciphertext stealing).
    #[test]
    fn ieee1619_vector_16_xts_aes128_18_byte_unit_cts() {
        let key1: [u8; 16] = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode("000102030405060708090a0b0c0d0e0f1011").unwrap();
        let ciphertext = hex::decode("d069444b7a7e0cab09e24447d24deb1fedbf").unwrap();
        let tweak: u128 = 0x123456789a;

        assert_eq!(plaintext.len(), 18);
        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 17: XTS-AES-128, 19-byte data unit (ciphertext stealing).
    #[test]
    fn ieee1619_vector_17_xts_aes128_19_byte_unit_cts() {
        let key1: [u8; 16] = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode("000102030405060708090a0b0c0d0e0f101112").unwrap();
        let ciphertext = hex::decode("e5df1351c0544ba1350b3363cd8ef4beedbf9d").unwrap();
        let tweak: u128 = 0x123456789a;

        assert_eq!(plaintext.len(), 19);
        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 18: XTS-AES-128, 20-byte data unit (ciphertext stealing).
    #[test]
    fn ieee1619_vector_18_xts_aes128_20_byte_unit_cts() {
        let key1: [u8; 16] = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode("000102030405060708090a0b0c0d0e0f10111213").unwrap();
        let ciphertext = hex::decode("9d84c813f719aa2c7be3f66171c7c5c2edbf9dac").unwrap();
        let tweak: u128 = 0x123456789a;

        assert_eq!(plaintext.len(), 20);
        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 4: XTS-AES-128, 512-byte (32-block) data unit, block-aligned.
    #[test]
    fn ieee1619_vector_04_xts_aes128_512_byte_unit() {
        let key1: [u8; 16] = hex::decode("27182818284590452353602874713526")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("31415926535897932384626433832795")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let ciphertext = hex::decode(
            "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c\
        c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412\
        328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce\
        93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265\
        5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8\
        a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434\
        1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c\
        5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e\
        94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc\
        1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3\
        e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344\
        b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd\
        74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752\
        afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e\
        bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d\
        eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
        )
        .unwrap();
        let tweak: u128 = 0;

        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 10: XTS-AES-256, 512-byte (32-block) data unit, block-aligned.
    #[test]
    fn ieee1619_vector_10_xts_aes256_512_byte_unit() {
        let key1: [u8; 32] =
            hex::decode("2718281828459045235360287471352662497757247093699959574966967627")
                .unwrap()
                .try_into()
                .unwrap();
        let key2: [u8; 32] =
            hex::decode("3141592653589793238462643383279502884197169399375105820974944592")
                .unwrap()
                .try_into()
                .unwrap();
        let xts = XtsCipher::new(aes256(key1), aes256(key2));
        let plaintext = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let ciphertext = hex::decode(
            "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b\
        5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd\
        5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0\
        c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca\
        2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0\
        b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f\
        93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec\
        583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a\
        84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1\
        505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae\
        9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29\
        a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac\
        6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f\
        645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385\
        1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa\
        773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151",
        )
        .unwrap();
        let tweak: u128 = 255;

        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    /// Vector 19: XTS-AES-128, 512-byte (32-block) data unit, block-aligned.
    #[test]
    fn ieee1619_vector_19_xts_aes128_512_byte_unit() {
        let key1: [u8; 16] = hex::decode("e0e1e2e3e4e5e6e7e8e9eaebecedeeef")
            .unwrap()
            .try_into()
            .unwrap();
        let key2: [u8; 16] = hex::decode("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
            .unwrap()
            .try_into()
            .unwrap();
        let xts = XtsCipher::new(aes128(key1), aes128(key2));
        let plaintext = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
        202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
        404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\
        606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
        808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
        a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
        c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
        e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let ciphertext = hex::decode(
            "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6\
        8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc\
        bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854\
        9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177\
        41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3\
        9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4\
        8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe\
        41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d\
        19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64\
        a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272\
        9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648\
        346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394\
        d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2\
        cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a\
        5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf\
        92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3",
        )
        .unwrap();
        let tweak: u128 = 728121033505;

        assert_eq!(
            xts.encrypt_data_unit(&plaintext, tweak).unwrap(),
            ciphertext
        );
        assert_eq!(
            xts.decrypt_data_unit(&ciphertext, tweak).unwrap(),
            plaintext
        );
    }

    // ================================================================
    // Equal key halves at engine level (RFC §2 scoping: the facade
    // rejects this; the engine must not).
    // ================================================================

    #[test]
    fn accepts_equal_key_halves_with_twofish() {
        let key = [0x77u8; 32];
        let xts = XtsCipher::new(
            Twofish::new_from_slice(&key).expect("32-byte key is valid"),
            Twofish::new_from_slice(&key).expect("32-byte key is valid"),
        );
        let plaintext = [0x11u8; 16];
        let ciphertext = xts.encrypt_data_unit(&plaintext, 5).expect("valid input");
        let round_tripped = xts
            .decrypt_data_unit(&ciphertext, 5)
            .expect("valid ciphertext");
        assert_eq!(round_tripped, plaintext);
    }

    // ================================================================
    // Length validation: all in oxifish-owned code, no reachable panic.
    // ================================================================

    fn twofish_pair() -> XtsCipher<Twofish> {
        XtsCipher::new(
            Twofish::new_from_slice(&[0x01u8; 32]).expect("valid key"),
            Twofish::new_from_slice(&[0x02u8; 32]).expect("valid key"),
        )
    }

    #[test]
    fn rejects_data_units_shorter_than_one_block() {
        let xts = twofish_pair();
        for len in [0usize, 1, 15] {
            let data = vec![0u8; len];
            assert_eq!(
                xts.encrypt_data_unit(&data, 0),
                Err(XtsError::InvalidLength { len })
            );
            assert_eq!(
                xts.decrypt_data_unit(&data, 0),
                Err(XtsError::InvalidLength { len })
            );
        }
    }

    #[test]
    fn rejects_data_units_longer_than_2_pow_20_blocks() {
        let xts = twofish_pair();
        let len = MAX_DATA_UNIT_BYTES + 1;
        let data = vec![0u8; len];
        assert_eq!(
            xts.encrypt_data_unit(&data, 0),
            Err(XtsError::InvalidLength { len })
        );
        assert_eq!(
            xts.decrypt_data_unit(&data, 0),
            Err(XtsError::InvalidLength { len })
        );
    }

    #[test]
    fn accepts_the_minimum_and_maximum_boundary_lengths() {
        let xts = twofish_pair();

        let min = vec![0x5Au8; MIN_DATA_UNIT_BYTES];
        assert!(xts.encrypt_data_unit(&min, 0).is_ok());

        // 16 MiB at the upper bound: a real allocation/transform, not a
        // shortcut, so the inclusive boundary is proven, not asserted.
        let max = vec![0x5Au8; MAX_DATA_UNIT_BYTES];
        let ciphertext = xts.encrypt_data_unit(&max, 0).expect("boundary is valid");
        assert_eq!(ciphertext.len(), MAX_DATA_UNIT_BYTES);
        assert_eq!(xts.decrypt_data_unit(&ciphertext, 0).unwrap(), max);
    }

    #[test]
    fn invalid_length_error_message_matches_the_catalog_shape() {
        let err = XtsError::InvalidLength { len: 5 };
        assert_eq!(
            err.to_string(),
            "XTS data unit must be 16 to 16777216 bytes, got 5 bytes"
        );
    }

    // ================================================================
    // Length preservation (pinned property) across every CTS residue.
    // ================================================================

    #[test]
    fn length_preservation_across_every_cts_residue() {
        let xts = twofish_pair();
        let mut rng = DeterministicRng::new(0x1EAF_C0DE_1EAF_C0DE);

        for residue in 0..BLOCK_SIZE {
            for blocks in 1..=3usize {
                let len = blocks * BLOCK_SIZE + residue;
                let mut plaintext = vec![0u8; len];
                rng.fill_bytes(&mut plaintext);
                let tweak = rng.next_u128();

                let ciphertext = xts
                    .encrypt_data_unit(&plaintext, tweak)
                    .unwrap_or_else(|e| panic!("len={len} residue={residue}: {e}"));
                assert_eq!(ciphertext.len(), len, "len={len} residue={residue}");

                let round_tripped = xts.decrypt_data_unit(&ciphertext, tweak).unwrap();
                assert_eq!(round_tripped, plaintext, "len={len} residue={residue}");
            }
        }
    }

    // ================================================================
    // Tweak edge encodings: 0, 1, 2^64, 2^128-1 (IEEE 1619's full
    // 128-bit tweak space; VeraCrypt/dm-crypt interop only ever presents
    // tweaks below 2^64).
    // ================================================================

    #[test]
    fn tweak_edge_encodings_round_trip_and_diverge() {
        let xts = twofish_pair();
        let plaintext = [0x5Au8; 33]; // exercises CTS too (33 % 16 == 1)

        let edges: [u128; 4] = [0, 1, 1u128 << 64, u128::MAX];
        let mut ciphertexts = Vec::new();
        for tweak in edges {
            let ciphertext = xts
                .encrypt_data_unit(&plaintext, tweak)
                .unwrap_or_else(|e| panic!("tweak={tweak}: {e}"));
            let round_tripped = xts.decrypt_data_unit(&ciphertext, tweak).unwrap();
            assert_eq!(round_tripped, plaintext.to_vec(), "tweak={tweak}");
            ciphertexts.push(ciphertext);
        }

        // Every edge tweak must produce a distinct ciphertext -- a tweak
        // that were silently ignored would collapse all four to the same
        // bytes.
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "tweak={} and tweak={} collided",
                    edges[i], edges[j]
                );
            }
        }
    }

    // ================================================================
    // Independent-implementation cross-validation vs the `xts-mode`
    // crate (dev-dependency oracle; see the RFC's Dependency Strategy)
    // with Twofish, over deterministic randomized keys/tweaks/lengths,
    // covering every ciphertext-stealing tail residue, run
    // bidirectionally (encrypt-ours/decrypt-theirs and the reverse) --
    // the strongest structural defense against a self-consistent
    // tweak-order-swap bug in either implementation.
    // ================================================================

    /// A tiny deterministic PRNG (SplitMix64) so randomized test inputs
    /// are reproducible across runs -- no `Instant::now()`-style seeding.
    struct DeterministicRng(u64);

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }

        fn next_u128(&mut self) -> u128 {
            (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
        }

        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let word = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        }
    }

    fn cross_validate_one(rng: &mut DeterministicRng, len: usize) {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        rng.fill_bytes(&mut key1);
        rng.fill_bytes(&mut key2);
        let mut plaintext = vec![0u8; len];
        rng.fill_bytes(&mut plaintext);
        let tweak = rng.next_u128();

        let ours = XtsCipher::new(
            Twofish::new_from_slice(&key1).expect("valid key"),
            Twofish::new_from_slice(&key2).expect("valid key"),
        );
        let theirs = Xts128::new(
            Twofish::new_from_slice(&key1).expect("valid key"),
            Twofish::new_from_slice(&key2).expect("valid key"),
        );
        let their_tweak = get_tweak_default(tweak);

        // encrypt ours / decrypt theirs
        let ciphertext_ours = ours
            .encrypt_data_unit(&plaintext, tweak)
            .unwrap_or_else(|e| panic!("len={len}: {e}"));
        let mut buf = ciphertext_ours.clone();
        theirs.decrypt_sector(&mut buf, their_tweak);
        assert_eq!(
            buf, plaintext,
            "encrypt-ours/decrypt-theirs disagree, len={len} tweak={tweak}"
        );

        // encrypt theirs / decrypt ours
        let mut buf2 = plaintext.clone();
        theirs.encrypt_sector(&mut buf2, their_tweak);
        let plaintext_ours = ours
            .decrypt_data_unit(&buf2, tweak)
            .unwrap_or_else(|e| panic!("len={len}: {e}"));
        assert_eq!(
            plaintext_ours, plaintext,
            "encrypt-theirs/decrypt-ours disagree, len={len} tweak={tweak}"
        );
    }

    #[test]
    fn bidirectional_cross_validation_against_xts_mode_every_cts_residue() {
        let mut rng = DeterministicRng::new(0xC0FFEE_D15EA5E5);

        for residue in 0..BLOCK_SIZE {
            for blocks in 1..=3usize {
                let len = blocks * BLOCK_SIZE + residue;
                cross_validate_one(&mut rng, len);
            }
        }
    }
}
