"""Tests for RFC 0001's streaming plumbing + buffer protocol.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 12 ("Streaming
plumbing + buffer protocol (copy while GIL held)"). Adds
`TwofishKey.encryptor`/`decryptor` -- the `TwofishSession` factories for
the four IV modes (cbc/ctr/cfb/ofb; `"ecb"` remains reachable only via
`ecb_encryptor`/`ecb_decryptor`, per slice 11) -- and widens
`TwofishSession.update`/`finalize` from `bytes`-only (slice 11's minimal
session core) to the full `Buffer` union (bytes/bytearray/memoryview),
via a `pyo3::buffer::PyBuffer` copy into engine-owned memory while the GIL
is held.

**Scope decision (documented, not a silent guess):** `iv` is required
(explicit-IV only) on both factories this slice, mirroring
`TwofishKey.encrypt`/`decrypt`'s slice-8 scope decision -- the RFC's
`iv=None` auto-generate overload is slice 13's deliverable ("Auto-IV").
`py.allow_threads` (releasing the GIL around the pure-Rust transform) is
explicitly named as a later slice's deliverable by the RFC bullet for this
slice ("copy while GIL held") and confirmed out of scope by slice 15's
title ("Misuse machine + DecryptionError + GIL release"); this slice's
mutate-after-update tests below prove the *copy* half of the soundness
invariant, which is everything observable without a second thread
concurrently running Python code during a Rust call (impossible without
GIL release).
"""

import pytest
from oxifish import Mode, Padding, TwofishKey, TwofishSession

KEY_16 = bytes(range(16))
KEY_24 = bytes(range(24))
KEY_32 = bytes(range(32))
IV = bytes(range(16, 32))

# RFC 0002 change 3: introspected from `Mode` rather than hand-enumerated
# (see tests/test_one_shot_modes.py's ALL_MODES/STREAM_MODES comment for the
# general rationale). Every `Mode` member takes an IV today (ECB, the one
# IV-less cipher mode, is deliberately excluded from `Mode` itself -- see
# `Mode`'s docstring in python/oxifish/__init__.py -- and reachable only via
# the separate `ecb_encryptor`/`ecb_decryptor` factories, which this module
# covers separately in tests/test_ecb.py). If a future IV-less member ever
# joins `Mode`, this list picking it up and the resulting `.iv`/round-trip
# tests failing loudly is the desired behavior -- it forces an explicit
# decision here rather than silently exempting the new member.
IV_MODES = list(Mode)
# Still an exclusion, not `list(Mode)`, since these call sites are
# specifically about the three non-CBC modes.
STREAM_MODES = [m for m in Mode if m != Mode.CBC]


class TestFactoryConstruction:
    """`encryptor`/`decryptor` return a `TwofishSession` reporting the
    matching `mode`/`direction`."""

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_encryptor_returns_a_session(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.encryptor(mode, iv=IV, padding=padding)
        assert isinstance(session, TwofishSession)

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_encryptor_mode_matches(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.encryptor(mode, iv=IV, padding=padding)
        assert session.mode == mode.value

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_encryptor_direction_is_encrypt(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.encryptor(mode, iv=IV, padding=padding)
        assert session.direction == "encrypt"

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_decryptor_mode_matches(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.decryptor(mode, iv=IV, padding=padding)
        assert session.mode == mode.value

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_decryptor_direction_is_decrypt(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.decryptor(mode, iv=IV, padding=padding)
        assert session.direction == "decrypt"

    def test_mode_defaults_to_cbc(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(iv=IV)
        assert session.mode == "cbc"

    def test_mode_string_and_enum_member_are_interchangeable(self) -> None:
        key = TwofishKey(KEY_16)
        via_enum = key.encryptor(Mode.CTR, iv=IV)
        via_string = key.encryptor("ctr", iv=IV)
        assert via_enum.mode == via_string.mode == "ctr"

    def test_fresh_session_per_call(self) -> None:
        key = TwofishKey(KEY_16)
        first = key.encryptor(Mode.CTR, iv=IV)
        second = key.encryptor(Mode.CTR, iv=IV)
        assert first is not second
        first.finalize(b"data")
        # `second` is untouched by `first`'s finalization.
        second.finalize(b"data")


class TestModeValidation:
    """Mode-string validation reuses the single `parse_mode` site --
    `"ecb"` gets no carve-out (ECB is reachable only via `ecb_encryptor`/
    `ecb_decryptor`)."""

    def test_encryptor_rejects_ecb_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'ecb': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key.encryptor("ecb", iv=IV)

    def test_decryptor_rejects_ecb_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'ecb': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key.decryptor("ecb", iv=IV)

    def test_encryptor_rejects_unknown_mode_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'bogus': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key.encryptor("bogus", iv=IV)

    def test_decryptor_rejects_unknown_mode_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'bogus': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key.decryptor("bogus", iv=IV)

    def test_encryptor_rejects_bad_iv_length(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key.encryptor(Mode.CBC, iv=b"short")

    def test_decryptor_rejects_bad_iv_length(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key.decryptor(Mode.CBC, iv=b"short")


class TestPaddingRejection:
    """RFC Contracts: stream modes reject *any* explicit `padding=`,
    including `"none"`; CBC's `None` default means PKCS7."""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_encryptor_rejects_explicit_padding_on_stream_modes(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match="padding is not supported"):
            key.encryptor(mode, iv=IV, padding=Padding.PKCS7)

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_encryptor_rejects_explicit_none_padding_on_stream_modes(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match="padding is not supported"):
            key.encryptor(mode, iv=IV, padding=Padding.NONE)

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_decryptor_rejects_explicit_padding_on_stream_modes(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match="padding is not supported"):
            key.decryptor(mode, iv=IV, padding=Padding.PKCS7)

    def test_cbc_omitted_padding_defaults_to_pkcs7(self) -> None:
        key = TwofishKey(KEY_16)
        via_default = key.encryptor(Mode.CBC, iv=IV).finalize(b"twenty-byte message!")
        via_explicit = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7).finalize(
            b"twenty-byte message!"
        )
        assert via_default == via_explicit


class TestIVProperty:
    """RFC Proposed Interface: `.iv` returns the IV bytes for IV modes,
    readable post-finalize."""

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_iv_returns_supplied_bytes(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.encryptor(mode, iv=IV, padding=padding)
        assert session.iv == IV

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_iv_is_readable_after_finalize(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        session = key.encryptor(mode, iv=IV, padding=padding)
        session.finalize(b"some data")
        assert session.iv == IV

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_decryptor_iv_is_readable_after_finalize(self, mode: Mode) -> None:
        # F24: the encrypt-session case is covered just above; decrypt
        # sessions get the same readability guarantee (RFC `.iv` property
        # docstring: "Readable after finalize()").
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        plaintext = b"decrypt session iv readability check"
        ciphertext = key.encrypt(plaintext, mode, iv=IV, padding=padding)

        session = key.decryptor(mode, iv=IV, padding=padding)
        session.finalize(ciphertext)
        assert session.iv == IV

    def test_iv_is_bytes(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        assert isinstance(session.iv, bytes)

    def test_decryptor_iv_returns_supplied_bytes(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.decryptor(Mode.OFB, iv=IV)
        assert session.iv == IV


class TestStreamingRoundTrip:
    """Chunked update()/finalize() must byte-match the one-shot
    `encrypt`/`decrypt` output, for a few chunk-size patterns per mode."""

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_single_update_then_empty_finalize_matches_one_shot(self, mode: Mode) -> None:
        key = TwofishKey(KEY_32)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        plaintext = b"a message that is not block aligned!"
        one_shot = key.encrypt(plaintext, mode, iv=IV, padding=padding)

        session = key.encryptor(mode, iv=IV, padding=padding)
        streamed = session.update(plaintext) + session.finalize()
        assert streamed == one_shot

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_one_byte_at_a_time_matches_one_shot(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        plaintext = bytes(range(37))  # unaligned length
        one_shot = key.encrypt(plaintext, mode, iv=IV, padding=padding)

        session = key.encryptor(mode, iv=IV, padding=padding)
        out = bytearray()
        for i in range(len(plaintext) - 1):
            out += session.update(plaintext[i : i + 1])
        out += session.finalize(plaintext[-1:])
        assert bytes(out) == one_shot

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_uneven_chunks_match_one_shot(self, mode: Mode) -> None:
        key = TwofishKey(KEY_24)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        plaintext = bytes(range(100, 100 + 53))
        one_shot = key.encrypt(plaintext, mode, iv=IV, padding=padding)

        session = key.encryptor(mode, iv=IV, padding=padding)
        chunks = [plaintext[:5], plaintext[5:5], plaintext[5:22], plaintext[22:41]]
        out = bytearray()
        for chunk in chunks:
            out += session.update(chunk)
        out += session.finalize(plaintext[41:])
        assert bytes(out) == one_shot

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_decrypt_round_trips_streamed_ciphertext(self, mode: Mode) -> None:
        key = TwofishKey(KEY_32)
        padding = None if mode != Mode.CBC else Padding.PKCS7
        plaintext = bytes(range(200, 200 + 45))
        ciphertext = key.encrypt(plaintext, mode, iv=IV, padding=padding)

        session = key.decryptor(mode, iv=IV, padding=padding)
        out = bytearray()
        out += session.update(ciphertext[:16])
        out += session.update(ciphertext[16:30])
        out += session.finalize(ciphertext[30:])
        assert bytes(out) == plaintext


class TestDecryptHoldbackTiming:
    """RFC `update()` docstring: for a padded (non-"none") DECRYPT session,
    feeding N aligned ciphertext blocks via `update()` yields N-1 blocks
    back -- the most recent complete block may carry padding and is held
    back until `finalize()`. Encrypt sessions have no holdback: `update()`
    flushes every complete block it receives immediately."""

    def test_cbc_pkcs7_decrypt_update_withholds_final_block(self) -> None:
        key = TwofishKey(KEY_32)
        plaintext = bytes(range(35))  # pads out to 3 full blocks (48 bytes)
        ciphertext = key.encrypt(plaintext, Mode.CBC, iv=IV, padding=Padding.PKCS7)
        assert len(ciphertext) == 48  # 3 aligned blocks in

        session = key.decryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        update_out = session.update(ciphertext)
        assert len(update_out) == 32  # N-1 = 2 blocks; the 3rd is held back

        finalize_out = session.finalize()
        assert update_out + finalize_out == plaintext

    def test_cbc_encrypt_session_has_no_holdback(self) -> None:
        key = TwofishKey(KEY_32)
        plaintext = bytes(range(32))  # 2 aligned blocks
        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        update_out = session.update(plaintext)
        # Encrypt flushes complete blocks eagerly -- both are returned now,
        # even though a further (all-padding) block is still pending.
        assert len(update_out) == 32


class TestEmptyMessageMatrix:
    """RFC Contracts: empty-message matrix, pinned by test -- extended here
    to non-ECB streaming sessions (one-shot: tests/test_one_shot_cbc.py;
    ECB sessions: tests/test_ecb.py). `encryptor(...).finalize()` with no
    `update()` call at all exercises the same empty-message path, engaging
    the padded-decrypt holdback machinery on the round-trip side.

    **Judgment call (documented, not a silent guess):** the RFC Contracts
    bullet groups paddings as pkcs7/ansix923/iso7816 producing exactly one
    full padding block for an empty message, and zeros/none producing an
    empty result -- zeros is grouped with none (both produce an empty
    result), matching the existing pins in
    tests/test_ecb.py::TestEmptyMessageMatrix and
    tests/test_one_shot_cbc.py::TestEmptyMessageMatrix.
    """

    @pytest.mark.parametrize("padding", [Padding.PKCS7, Padding.ANSIX923, Padding.ISO7816])
    def test_cbc_padded_schemes_encrypt_empty_to_one_full_block(self, padding: Padding) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encryptor(Mode.CBC, iv=IV, padding=padding).finalize()
        assert len(ciphertext) == 16

    @pytest.mark.parametrize("padding", [Padding.PKCS7, Padding.ANSIX923, Padding.ISO7816])
    def test_cbc_padded_schemes_empty_message_round_trips(self, padding: Padding) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encryptor(Mode.CBC, iv=IV, padding=padding).finalize()
        recovered = key.decryptor(Mode.CBC, iv=IV, padding=padding).finalize(ciphertext)
        assert recovered == b""

    @pytest.mark.parametrize("padding", [Padding.ZEROS, Padding.NONE])
    def test_cbc_zeros_and_none_encrypt_empty_to_empty(self, padding: Padding) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encryptor(Mode.CBC, iv=IV, padding=padding).finalize()
        assert ciphertext == b""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_stream_modes_encrypt_empty_to_empty(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encryptor(mode, iv=IV).finalize()
        assert ciphertext == b""


class TestIVBufferTypes:
    """Bonus pin: `iv` accepts any `Buffer` (bytearray/memoryview), not
    just `bytes`, at the streaming-session factories too (RFC Contracts:
    "iv parameters accept any Buffer ... coerced like data" -- widened from
    bytes-only in stage-4 review, finding 3). Mirrors
    TestBufferProtocolAcceptance's `data`/`update`/`finalize` coverage, but
    for `iv=` on `encryptor`/`decryptor`."""

    def test_encryptor_accepts_bytearray_iv_and_matches_bytes_iv(self) -> None:
        key = TwofishKey(KEY_16)
        plaintext = b"streamed iv buffer type check"

        via_bytes = key.encryptor(Mode.CTR, iv=IV)
        out_bytes = via_bytes.update(plaintext) + via_bytes.finalize()

        via_bytearray = key.encryptor(Mode.CTR, iv=bytearray(IV))
        out_bytearray = via_bytearray.update(plaintext) + via_bytearray.finalize()

        assert out_bytes == out_bytearray

    def test_decryptor_accepts_memoryview_iv_and_round_trips(self) -> None:
        key = TwofishKey(KEY_16)
        plaintext = b"streamed iv buffer type check"
        ciphertext = key.encrypt(plaintext, Mode.CTR, iv=IV)

        session = key.decryptor(Mode.CTR, iv=memoryview(IV))
        recovered = session.update(ciphertext) + session.finalize()
        assert recovered == plaintext


class TestBufferProtocolAcceptance:
    """`update`/`finalize` accept `bytes`/`bytearray`/`memoryview`
    interchangeably (RFC: `Buffer` type alias)."""

    def test_update_accepts_bytearray(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        out = session.update(bytearray(b"hello, world"))
        assert isinstance(out, bytes)
        assert len(out) == len(b"hello, world")

    def test_update_accepts_memoryview(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        out = session.update(memoryview(b"hello, world"))
        assert isinstance(out, bytes)
        assert len(out) == len(b"hello, world")

    def test_finalize_accepts_bytearray(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.ecb_encryptor(padding=Padding.NONE)
        out = session.finalize(bytearray(range(16)))
        assert len(out) == 16

    def test_finalize_accepts_memoryview(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.ecb_encryptor(padding=Padding.NONE)
        out = session.finalize(memoryview(bytes(range(16))))
        assert len(out) == 16

    def test_bytes_bytearray_memoryview_produce_identical_output(self) -> None:
        key = TwofishKey(KEY_16)
        payload = bytes(range(16)) * 3

        s1 = key.encryptor(Mode.CFB, iv=IV)
        out_bytes = s1.update(payload) + s1.finalize()

        s2 = key.encryptor(Mode.CFB, iv=IV)
        out_bytearray = s2.update(bytearray(payload)) + s2.finalize()

        s3 = key.encryptor(Mode.CFB, iv=IV)
        out_memoryview = s3.update(memoryview(payload)) + s3.finalize()

        assert out_bytes == out_bytearray == out_memoryview

    def test_update_rejects_non_buffer_type(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        with pytest.raises((TypeError, ValueError)):
            session.update(12345)  # type: ignore[arg-type]

    def test_finalize_rejects_non_buffer_type(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        with pytest.raises((TypeError, ValueError)):
            session.finalize(12345)  # type: ignore[arg-type]


class TestMutateAfterUpdateProvesCopySemantics:
    """RFC Concurrency contract: buffer-protocol input is copied into
    engine-owned memory while the GIL is held. Mutating the source
    `bytearray` after `update()` returns must not retroactively change
    what was already ingested/output."""

    def test_mutating_source_bytearray_after_update_does_not_change_output(self) -> None:
        key = TwofishKey(KEY_16)
        original = b"0123456789ABCDEF" * 2  # 32 bytes, CTR is byte-granular
        source = bytearray(original)

        session = key.encryptor(Mode.CTR, iv=IV)
        first_output = session.update(source)

        # Mutate the source buffer in place after update() has returned.
        source[:] = b"\x00" * len(source)

        # An independent session encrypting the untouched original bytes
        # must match what the mutated-source session produced -- proving
        # the mutation (which happened strictly after update() returned)
        # had no effect on already-computed output.
        reference_session = key.encryptor(Mode.CTR, iv=IV)
        reference_output = reference_session.update(original)

        assert first_output == reference_output

    def test_mutating_source_bytearray_after_finalize_does_not_change_output(self) -> None:
        key = TwofishKey(KEY_16)
        original = bytes(range(16))
        source = bytearray(original)

        session = key.ecb_encryptor(padding=Padding.NONE)
        ciphertext = session.finalize(source)

        source[:] = b"\xff" * 16

        reference_session = key.ecb_encryptor(padding=Padding.NONE)
        reference_ciphertext = reference_session.finalize(original)

        assert ciphertext == reference_ciphertext

    def test_mutating_source_bytearray_after_cbc_update_does_not_change_buffered_residue(
        self,
    ) -> None:
        # Exercises the engine's `pending` buffer specifically: a
        # sub-block chunk that gets copied into `pending` internally, not
        # emitted immediately -- if the copy-while-GIL-held discipline were
        # violated, mutating `source` after `update()` could corrupt the
        # buffered residue that later chunks complete.
        key = TwofishKey(KEY_16)
        original = b"short"  # sub-block residue, gets buffered internally
        source = bytearray(original)

        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        emitted = session.update(source)
        assert emitted == b""  # buffered, nothing emitted yet

        source[:] = b"\x00" * len(source)
        ciphertext = session.finalize()

        reference_session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        reference_ciphertext = reference_session.update(original) + reference_session.finalize()

        assert ciphertext == reference_ciphertext


class TestSessionStateMachine:
    """Misuse matrix for IV-mode sessions (ECB coverage lives in
    tests/test_ecb.py): `update`/`finalize` after `finalize()` raise
    `RuntimeError` with the catalogued message."""

    def test_update_after_finalize_raises_runtime_error(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        session.finalize(b"data")
        with pytest.raises(RuntimeError, match="session is already finalized"):
            session.update(b"more")

    def test_finalize_after_finalize_raises_runtime_error(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR, iv=IV)
        session.finalize(b"data")
        with pytest.raises(RuntimeError, match="session is already finalized"):
            session.finalize()

    def test_properties_stay_readable_after_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CFB, iv=IV)
        session.finalize(b"data")
        assert session.mode == "cfb"
        assert session.direction == "encrypt"
        assert session.iv == IV


class TestRepr:
    """`__repr__` shows mode, direction, session state, and iv -- never key
    material (RFC Contracts: `__repr__`). Session-state labels are
    "fresh"/"streaming"/"finalized" (src/engine.rs's `state_label`)."""

    def test_repr_shows_mode_direction_and_iv(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.OFB, iv=IV)
        r = repr(session)
        assert "ofb" in r
        assert "encrypt" in r
        assert IV.hex() in r

    def test_repr_shows_fresh_state(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.OFB, iv=IV)
        assert "fresh" in repr(session)

    def test_repr_shows_streaming_state_after_update(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.OFB, iv=IV)
        session.update(b"some data")
        assert "streaming" in repr(session)

    def test_repr_shows_finalized_state_after_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.OFB, iv=IV)
        session.finalize(b"some data")
        assert "finalized" in repr(session)

    def test_repr_never_shows_key_material(self) -> None:
        raw = bytes.fromhex("ab" * 32)
        key = TwofishKey(raw)
        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        r = repr(session)
        assert raw.hex() not in r
