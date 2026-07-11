"""Hypothesis chunking-invariance suite for RFC 0001's new surface.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 14 ("Hypothesis
chunking-invariance suite (budgeted; CI profile)"). Property: for every
applicable mode x padding combination, any random partition of a message
run through `TwofishSession.update()` calls must byte-match the
corresponding one-shot output -- both directions (encrypt and decrypt).
RFC Contracts: "Engine unification" makes this a structural guarantee
(one-shots and sessions share the same `ingest`/`close_out` engine path),
not a coincidence of two independently correct implementations; this
suite is the regression net that pins it.

**Combo list (13, per the RFC's Testing Strategy bullet: "for every
applicable mode x padding combination (13: CBC/ECB x 5 paddings + 3
stream modes)")**: CBC x {pkcs7, none, iso7816, ansix923, zeros} (5) +
ECB x {pkcs7, none, iso7816, ansix923, zeros} (5) + {ctr, cfb, ofb} (3,
no padding parameter) = 13.

**Budget (per the RFC's Testing Strategy bullet):** `st.binary(max_size=
200)` payload data, `@settings(max_examples=25, deadline=None)` per
combo -- registered as the active *default* Hypothesis profile in
`tests/conftest.py` so this applies with no extra flags, and repeated
explicitly here as the decorator budget the RFC calls out by name. The
`padding=none` combos use a dedicated block-aligned strategy instead of
raw `st.binary(max_size=200)` -- `padding="none"` enforces alignment as a
caller-side contract (RFC Contracts), which is a *different* property
(tested in test_one_shot_cbc.py/test_ecb.py's misuse matrices), not the
chunking-invariance property under test here; feeding it misaligned data
would just be asserting two paths raise the same exception, not that they
agree on ciphertext bytes.

**Chunk-partition strategy:** cut points are drawn from Hypothesis-
controlled `st.data()` (not a hand-rolled random source), so Hypothesis's
shrinker can shrink a failing partition. Cut points are *not*
deduplicated before slicing -- a duplicate cut point naturally yields a
`b""` chunk at that position, so `update(b"")` mid-stream is exercised as
an ordinary consequence of the strategy, not a bolted-on special case.

**Fixed (non-Hypothesis) examples, per the RFC's explicit carve-out**
("the all-1-byte-chunks case is a small fixed example test per mode
(bounded cost), not folded into the random strategy"): one-byte-at-a-time
chunking for cbc/ecb/ctr/cfb/ofb, and the "zeros" straddle case (RFC:
"Includes the zeros-straddle case") -- the same tricky plaintext pinned
in test_one_shot_cbc.py's `TestZerosScopedToFinalBlock`, now chunked at
several splits that land inside the straddling zero run.

**Re-homed properties** (RFC slice-14 bullet: "re-homed determinism/
differentiation properties" -- re-homed here, not deferred to slice 16,
per the bullet's own wording): ECB determinism and cross-mode output
differentiation from the old `tests/test_hypothesis.py`, ported onto the
new `TwofishKey`/`TwofishSession` surface as genuine Hypothesis
properties (the new surface's example-based suites already cover fixed
cross-mode/determinism cases; these are the property-based versions).
Invalid key/IV-length rejection is also re-homed as a property here.
`tests/test_hypothesis.py` itself is untouched -- it tests the *old* API,
which is not deleted until slice 16.
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from oxifish import Mode, Padding, TwofishKey, TwofishSession

KEY = bytes(range(16))
IV = bytes(range(16, 32))

# RFC 0002 change 3: introspected from `Padding` rather than hand-enumerated
# (see tests/test_ecb.py's ALL_PADDINGS comment for the general rationale).
# Both CBC and ECB exercise every padding scheme here -- unlike
# test_one_shot_cbc.py's CBC-only suite, this module's payload strategy
# (`_payload_strategy`) already special-cases `Padding.NONE` to draw
# block-aligned data, so there is no unaligned-plaintext reason to exclude
# it -- so both are the unfiltered `list(Padding)`.
CBC_PADDINGS = list(Padding)
ECB_PADDINGS = list(Padding)
# RFC 0002 change 3: introspected from `Mode` rather than hand-enumerated
# (see tests/test_one_shot_modes.py's ALL_MODES/STREAM_MODES comment for
# the full rationale); still an exclusion, not `list(Mode)`, since these
# call sites are specifically about the three non-CBC modes.
STREAM_MODES = [m for m in Mode if m != Mode.CBC]

COMBO_BUDGET = settings(max_examples=25, deadline=None)

_valid_key_lengths = st.sampled_from([16, 24, 32])
keys_strategy = _valid_key_lengths.flatmap(lambda n: st.binary(min_size=n, max_size=n))


def _payload_strategy(padding: Padding | None) -> st.SearchStrategy[bytes]:
    """`st.binary(max_size=200)` for every combo except `padding=none`,
    which must be block-aligned (a caller-side contract, not something
    this suite's property is about -- see module docstring)."""
    if padding is Padding.NONE:
        return st.integers(min_value=0, max_value=12).flatmap(
            lambda n: st.binary(min_size=n * 16, max_size=n * 16)
        )
    return st.binary(max_size=200)


def _draw_partition(data: st.DataObject, payload: bytes, label: str) -> list[bytes]:
    """Draw a random partition of `payload` into chunks from
    Hypothesis-controlled cut points, so a failing partition shrinks.
    Cut points are kept un-deduplicated -- duplicates yield `b""` chunks,
    covering the empty-chunk edge case as an ordinary consequence rather
    than a special-cased branch.
    """
    cut_points = data.draw(
        st.lists(st.integers(min_value=0, max_value=len(payload)), max_size=20),
        label=f"{label}_cuts",
    )
    points = sorted([0, len(payload), *cut_points])
    return [payload[a:b] for a, b in zip(points, points[1:], strict=False)]


def _stream(session: TwofishSession, chunks: list[bytes]) -> bytes:
    out = bytearray()
    for chunk in chunks:
        out += session.update(chunk)
    out += session.finalize()
    return bytes(out)


class TestCBCChunkingInvariance:
    """CBC x 5 paddings (10 of the 13 combos' CBC half)."""

    @pytest.mark.parametrize("padding", CBC_PADDINGS)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_encrypt_matches_one_shot(self, padding: Padding, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(_payload_strategy(padding), label="payload")
        chunks = _draw_partition(data, payload, "payload")

        one_shot = key.encrypt(payload, Mode.CBC, iv=IV, padding=padding)
        session = key.encryptor(Mode.CBC, iv=IV, padding=padding)
        assert _stream(session, chunks) == one_shot

    @pytest.mark.parametrize("padding", CBC_PADDINGS)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_decrypt_matches_one_shot(self, padding: Padding, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(_payload_strategy(padding), label="payload")
        ciphertext = key.encrypt(payload, Mode.CBC, iv=IV, padding=padding)
        # RFC-decided (not this suite's property): "zeros" decrypt of a
        # ciphertext shorter than one full block is a `DecryptionFailed`,
        # not a value to compare -- only reachable here via
        # padding=zeros + payload=b"" (RFC's empty-message matrix: zeros
        # encrypts b"" to b""). Chunking invariance is not this property;
        # both one-shot and chunked paths would raise identically anyway.
        assume(not (padding is Padding.ZEROS and len(ciphertext) == 0))
        chunks = _draw_partition(data, ciphertext, "ciphertext")

        one_shot = key.decrypt(ciphertext, Mode.CBC, iv=IV, padding=padding)
        session = key.decryptor(Mode.CBC, iv=IV, padding=padding)
        assert _stream(session, chunks) == one_shot


class TestECBChunkingInvariance:
    """ECB x 5 paddings (the other 5 of the 13 combos). ECB has no
    one-shot `encrypt`/`decrypt` (it is unreachable via `Mode`); the
    reference here is a fresh session's single `finalize(payload)` call --
    itself the degenerate one-chunk case of the same property, per the
    RFC's `ecb_encryptor(padding=...).finalize(block)` one-shot idiom."""

    @pytest.mark.parametrize("padding", ECB_PADDINGS)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_encrypt_matches_one_shot(self, padding: Padding, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(_payload_strategy(padding), label="payload")
        chunks = _draw_partition(data, payload, "payload")

        one_shot = key.ecb_encryptor(padding=padding).finalize(payload)
        session = key.ecb_encryptor(padding=padding)
        assert _stream(session, chunks) == one_shot

    @pytest.mark.parametrize("padding", ECB_PADDINGS)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_decrypt_matches_one_shot(self, padding: Padding, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(_payload_strategy(padding), label="payload")
        ciphertext = key.ecb_encryptor(padding=padding).finalize(payload)
        # See the matching comment in TestCBCChunkingInvariance.
        assume(not (padding is Padding.ZEROS and len(ciphertext) == 0))
        chunks = _draw_partition(data, ciphertext, "ciphertext")

        one_shot = key.ecb_decryptor(padding=padding).finalize(ciphertext)
        session = key.ecb_decryptor(padding=padding)
        assert _stream(session, chunks) == one_shot


class TestStreamModeChunkingInvariance:
    """ctr/cfb/ofb (the final 3 of the 13 combos): no padding parameter."""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_encrypt_matches_one_shot(self, mode: Mode, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(st.binary(max_size=200), label="payload")
        chunks = _draw_partition(data, payload, "payload")

        one_shot = key.encrypt(payload, mode, iv=IV)
        session = key.encryptor(mode, iv=IV)
        assert _stream(session, chunks) == one_shot

    @pytest.mark.parametrize("mode", STREAM_MODES)
    @given(data=st.data())
    @COMBO_BUDGET
    def test_decrypt_matches_one_shot(self, mode: Mode, data: st.DataObject) -> None:
        key = TwofishKey(KEY)
        payload = data.draw(st.binary(max_size=200), label="payload")
        ciphertext = key.encrypt(payload, mode, iv=IV)
        chunks = _draw_partition(data, ciphertext, "ciphertext")

        one_shot = key.decrypt(ciphertext, mode, iv=IV)
        session = key.decryptor(mode, iv=IV)
        assert _stream(session, chunks) == one_shot


class TestOneByteAtATimeFixedExamples:
    """RFC Testing Strategy: "the all-1-byte-chunks case is a small fixed
    example test per mode (bounded cost), not folded into the random
    strategy." One test per mode (cbc, ecb, ctr, cfb, ofb) -- a
    representative padding for the two block modes, none for the three
    stream modes."""

    PAYLOAD = bytes(range(37))  # deliberately unaligned length

    def test_cbc_one_byte_at_a_time(self) -> None:
        key = TwofishKey(KEY)
        one_shot = key.encrypt(self.PAYLOAD, Mode.CBC, iv=IV, padding=Padding.PKCS7)

        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        out = bytearray()
        for i in range(len(self.PAYLOAD)):
            out += session.update(self.PAYLOAD[i : i + 1])
        out += session.finalize()
        assert bytes(out) == one_shot

    def test_ecb_one_byte_at_a_time(self) -> None:
        key = TwofishKey(KEY)
        one_shot = key.ecb_encryptor(padding=Padding.PKCS7).finalize(self.PAYLOAD)

        session = key.ecb_encryptor(padding=Padding.PKCS7)
        out = bytearray()
        for i in range(len(self.PAYLOAD)):
            out += session.update(self.PAYLOAD[i : i + 1])
        out += session.finalize()
        assert bytes(out) == one_shot

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_stream_mode_one_byte_at_a_time(self, mode: Mode) -> None:
        key = TwofishKey(KEY)
        one_shot = key.encrypt(self.PAYLOAD, mode, iv=IV)

        session = key.encryptor(mode, iv=IV)
        out = bytearray()
        for i in range(len(self.PAYLOAD)):
            out += session.update(self.PAYLOAD[i : i + 1])
        out += session.finalize()
        assert bytes(out) == one_shot


class TestZerosStraddleChunkingInvariance:
    """RFC Testing Strategy: the chunking-invariance property "includes
    the zeros-straddle case" -- the same tricky plaintext from
    test_one_shot_cbc.py's `TestZerosScopedToFinalBlock` (a genuine zero
    run ending exactly at the held-back final block's boundary), now
    split across `update()` chunks at several points *inside* that zero
    run, checked against the one-shot zeros ciphertext."""

    # First 16-byte block genuinely ends in eight 0x00 bytes; the 4-byte
    # "tail" is the incomplete final block zero-padded by encryption.
    STRADDLE_PLAINTEXT = b"real-dat" + b"\x00" * 8 + b"tail"  # 20 bytes

    @pytest.mark.parametrize("split", [1, 5, 8, 13, 16, 18])
    def test_cbc_zeros_straddle_chunked_matches_one_shot(self, split: int) -> None:
        key = TwofishKey(KEY)
        one_shot = key.encrypt(self.STRADDLE_PLAINTEXT, Mode.CBC, iv=IV, padding=Padding.ZEROS)

        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.ZEROS)
        out = session.update(self.STRADDLE_PLAINTEXT[:split])
        out += session.update(self.STRADDLE_PLAINTEXT[split:])
        out += session.finalize()
        assert out == one_shot

    @pytest.mark.parametrize("split", [1, 5, 8, 13, 16, 18])
    def test_ecb_zeros_straddle_chunked_matches_one_shot(self, split: int) -> None:
        key = TwofishKey(KEY)
        one_shot = key.ecb_encryptor(padding=Padding.ZEROS).finalize(self.STRADDLE_PLAINTEXT)

        session = key.ecb_encryptor(padding=Padding.ZEROS)
        out = session.update(self.STRADDLE_PLAINTEXT[:split])
        out += session.update(self.STRADDLE_PLAINTEXT[split:])
        out += session.finalize()
        assert out == one_shot


class TestReHomedECBDeterminism:
    """Re-homed from tests/test_hypothesis.py's `TestECBProperties.
    test_ecb_deterministic` -- same key + same block always produces the
    same ciphertext -- ported onto the new
    `ecb_encryptor(padding=Padding.NONE)` surface."""

    @given(key=keys_strategy, block=st.binary(min_size=16, max_size=16))
    @COMBO_BUDGET
    def test_ecb_deterministic(self, key: bytes, block: bytes) -> None:
        ciphertext_1 = TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(block)
        ciphertext_2 = TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(block)
        assert ciphertext_1 == ciphertext_2


class TestReHomedCrossModeDifferentiation:
    """Re-homed from tests/test_hypothesis.py's `TestCrossMode.
    test_modes_produce_different_output` -- ported onto the new one-shot
    `encrypt` surface, plus a strengthened variant: the old property only
    compared CBC (padded, longer) against CTR (unpadded), a difference
    trivially explained by length; the three *equal-length* stream modes
    (ctr/cfb/ofb) below is a genuine content-differentiation check."""

    @given(key=keys_strategy, plaintext=st.binary(min_size=1, max_size=200))
    @COMBO_BUDGET
    def test_cbc_and_ctr_produce_different_output(self, key: bytes, plaintext: bytes) -> None:
        key_obj = TwofishKey(key)
        cbc = key_obj.encrypt(plaintext, Mode.CBC, iv=IV, padding=Padding.PKCS7)
        ctr = key_obj.encrypt(plaintext, Mode.CTR, iv=IV)
        assert cbc != ctr

    @given(key=keys_strategy, plaintext=st.binary(min_size=32, max_size=200))
    @COMBO_BUDGET
    def test_ctr_differs_from_cfb_and_ofb(self, key: bytes, plaintext: bytes) -> None:
        # min_size=32 (a full second block, not just "over one block"):
        # CTR/CFB/OFB all derive their first-block keystream identically
        # from E(IV) -- they only diverge starting the *second* block
        # (counter increment vs. ciphertext feedback vs. output feedback)
        # -- so a <=16-byte plaintext can produce byte-identical output
        # across all three modes by construction, not by coincidence.
        # min_size=32 (rather than 17, slice 17's fix -- RFC 0001 slice 17,
        # "Cleanup") guarantees a *full* 16-byte differing region rather
        # than a single differing byte: at min_size=17 the two second-block
        # keystreams differ across all 128 bits, but only one output byte
        # is ever compared, leaving a genuine (if small, ~1/256)
        # coincidental-collision chance that Hypothesis can and did
        # eventually find. A full differing block drops that collision
        # probability to ~2^-128, i.e. cryptographically negligible.
        #
        # CFB vs. OFB deliberately excluded from this comparison: for an
        # all-zero plaintext, CFB's second-block feedback register (the
        # previous *ciphertext* block, which equals E(IV) when plaintext
        # block 1 is zero) coincides exactly with OFB's second-block
        # feedback (E(IV), fed back unconditionally) -- a genuine
        # mathematical identity of the two modes on that input, not a
        # bug, so "CFB != OFB" is not a universally true property.
        key_obj = TwofishKey(key)
        ctr = key_obj.encrypt(plaintext, Mode.CTR, iv=IV)
        cfb = key_obj.encrypt(plaintext, Mode.CFB, iv=IV)
        ofb = key_obj.encrypt(plaintext, Mode.OFB, iv=IV)
        assert ctr != cfb
        assert ctr != ofb


class TestReHomedInvalidLengthRejection:
    """Re-homed from tests/test_hypothesis.py's `TestInvalidInputs` --
    bad key/IV lengths raise `ValueError` -- ported onto the new
    `TwofishKey`/`encrypt`/`encryptor` surface."""

    @given(key=st.binary(max_size=64).filter(lambda k: len(k) not in (16, 24, 32)))
    @COMBO_BUDGET
    def test_invalid_key_length_rejected(self, key: bytes) -> None:
        with pytest.raises(ValueError):
            TwofishKey(key)

    @given(iv=st.binary(max_size=64).filter(lambda iv: len(iv) != 16))
    @COMBO_BUDGET
    def test_invalid_iv_length_rejected_by_encrypt(self, iv: bytes) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError):
            key.encrypt(b"data", Mode.CBC, iv=iv, padding=Padding.PKCS7)

    @given(iv=st.binary(max_size=64).filter(lambda iv: len(iv) != 16))
    @COMBO_BUDGET
    def test_invalid_iv_length_rejected_by_encryptor(self, iv: bytes) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError):
            key.encryptor(Mode.CTR, iv=iv)
