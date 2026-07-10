"""Tests for RFC 0001's ECB factories + KATs.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 11 ("ECB
factories + KATs"). Adds `TwofishKey.ecb_encryptor`/`ecb_decryptor`,
returning a `TwofishSession` -- the sole way to reach ECB on the new
surface (excluded from `Mode` and from `encrypt`/`decrypt`/`encryptor`/
`decryptor`, per slice 10's `"ecb"`-string rejection).

**Scope decision (documented, not a silent guess):** the RFC's slice 12
("Streaming plumbing + buffer protocol") is titled for the full session
core -- `update`/`finalize` over the engine, plus `Buffer`
(bytes/bytearray/memoryview) input handling with the GIL-release-after-copy
soundness discipline. This slice needs a minimal session core to make
`ecb_encryptor`/`ecb_decryptor` usable at all (the one-shot ECB idiom in
the RFC's usage example has no other route), so `TwofishSession.update`/
`finalize` land here already -- but scoped to `bytes` input only.
`bytearray`/`memoryview` support is deferred to slice 12, where the real
work (buffer-protocol extraction + copy-while-GIL-held) actually lives;
widening the type signature without that work would be a lie. Auto-IV
(`TwofishSession.iv` populated for the four IV modes) is slice 13's
deliverable and irrelevant here -- ECB sessions never have an IV at all.
"""

import pytest
from oxifish import Padding, TwofishKey, TwofishSession

KEY_16 = bytes(range(16))
KEY_24 = bytes(range(24))
KEY_32 = bytes(range(32))

ALL_PADDINGS = [
    Padding.PKCS7,
    Padding.ISO7816,
    Padding.ANSIX923,
    Padding.ZEROS,
    Padding.NONE,
]


class TestFactoryConstruction:
    """`ecb_encryptor`/`ecb_decryptor` return a `TwofishSession` reporting
    `mode == "ecb"` and the matching `direction`."""

    def test_ecb_encryptor_returns_a_session(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        assert isinstance(session, TwofishSession)

    def test_ecb_encryptor_mode_is_ecb(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        assert session.mode == "ecb"

    def test_ecb_encryptor_direction_is_encrypt(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        assert session.direction == "encrypt"

    def test_ecb_decryptor_mode_is_ecb(self) -> None:
        session = TwofishKey(KEY_16).ecb_decryptor(padding=Padding.NONE)
        assert session.mode == "ecb"

    def test_ecb_decryptor_direction_is_decrypt(self) -> None:
        session = TwofishKey(KEY_16).ecb_decryptor(padding=Padding.NONE)
        assert session.direction == "decrypt"

    def test_padding_is_mandatory_keyword_only(self) -> None:
        # RFC Contracts: "ECB factories require explicit padding=" -- no
        # PKCS7-by-default carve-out, unlike `encrypt`/`decrypt`.
        with pytest.raises(TypeError):
            TwofishKey(KEY_16).ecb_encryptor()  # type: ignore[call-arg]

    def test_decryptor_padding_is_mandatory_keyword_only(self) -> None:
        with pytest.raises(TypeError):
            TwofishKey(KEY_16).ecb_decryptor()  # type: ignore[call-arg]

    def test_padding_string_and_enum_member_are_interchangeable(self) -> None:
        key = TwofishKey(KEY_16)
        block = bytes(range(16))
        via_enum = key.ecb_encryptor(padding=Padding.NONE).finalize(block)
        via_string = key.ecb_encryptor(padding="none").finalize(block)
        assert via_enum == via_string

    def test_rejects_unknown_padding_string(self) -> None:
        with pytest.raises(
            ValueError,
            match=r"invalid padding 'bogus': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'",
        ):
            TwofishKey(KEY_16).ecb_encryptor(padding="bogus")

    def test_decryptor_rejects_unknown_padding_string(self) -> None:
        with pytest.raises(
            ValueError,
            match=r"invalid padding 'bogus': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'",
        ):
            TwofishKey(KEY_16).ecb_decryptor(padding="bogus")

    def test_fresh_session_per_call(self) -> None:
        # Each factory call constructs an independent session -- state on
        # one session (e.g. finalization) must not leak to another.
        key = TwofishKey(KEY_16)
        first = key.ecb_encryptor(padding=Padding.NONE)
        second = key.ecb_encryptor(padding=Padding.NONE)
        assert first is not second
        first.finalize(bytes(16))
        # `second` is untouched by `first`'s finalization.
        second.finalize(bytes(16))


class TestOneLinerIdiom:
    """The RFC's usage example: `key.ecb_encryptor(padding=Padding.NONE)
    .finalize(block)` is a complete one-shot KAT/interop path -- the load-
    bearing reason `finalize(data=b"")` takes a parameter at all."""

    def test_single_expression_encrypt(self) -> None:
        key = TwofishKey(KEY_16)
        block = bytes(range(16))
        ciphertext = key.ecb_encryptor(padding=Padding.NONE).finalize(block)
        assert len(ciphertext) == 16

    def test_single_expression_decrypt_round_trips(self) -> None:
        key = TwofishKey(KEY_32)
        block = bytes(range(16))
        ciphertext = key.ecb_encryptor(padding=Padding.NONE).finalize(block)
        plaintext = key.ecb_decryptor(padding=Padding.NONE).finalize(ciphertext)
        assert plaintext == block

    def test_finalize_default_data_is_empty(self) -> None:
        # `finalize()` with no argument defaults `data` to b"".
        key = TwofishKey(KEY_16)
        session = key.ecb_encryptor(padding=Padding.PKCS7)
        # Empty message + pkcs7 padding -> exactly one full padding block
        # (RFC Contracts: empty-message matrix).
        assert len(session.finalize()) == 16


class TestNoIV:
    """RFC Proposed Interface: ECB sessions have no IV; `.iv` raises
    `AttributeError` at runtime."""

    def test_encryptor_iv_raises_attribute_error(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        with pytest.raises(AttributeError):
            _ = session.iv

    def test_decryptor_iv_raises_attribute_error(self) -> None:
        session = TwofishKey(KEY_16).ecb_decryptor(padding=Padding.NONE)
        with pytest.raises(AttributeError):
            _ = session.iv

    def test_iv_still_raises_after_finalize(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        with pytest.raises(AttributeError):
            _ = session.iv

    def test_iv_descriptor_is_visible_in_dir(self) -> None:
        # A PyO3 limitation the RFC explicitly accepts: the getter stays
        # visible in dir() even though every access raises.
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        assert "iv" in dir(session)


class TestSessionStateMachine:
    """Misuse matrix (scoped to ECB this slice): `update`/`finalize` after
    `finalize()` raise `RuntimeError` with the catalogued message."""

    def test_update_after_finalize_raises_runtime_error(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        with pytest.raises(RuntimeError, match="session is already finalized"):
            session.update(bytes(16))

    def test_finalize_after_finalize_raises_runtime_error(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        with pytest.raises(RuntimeError, match="session is already finalized"):
            session.finalize()

    def test_decryptor_update_after_finalize_raises_runtime_error(self) -> None:
        session = TwofishKey(KEY_16).ecb_decryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        with pytest.raises(RuntimeError, match="session is already finalized"):
            session.update(bytes(16))

    def test_properties_stay_readable_after_finalize(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        assert session.mode == "ecb"
        assert session.direction == "encrypt"

    def test_update_then_finalize_matches_one_shot(self) -> None:
        key = TwofishKey(KEY_32)
        msg = bytes(range(100, 132))  # 2 aligned blocks
        one_shot = key.ecb_encryptor(padding=Padding.NONE).finalize(msg)

        session = key.ecb_encryptor(padding=Padding.NONE)
        streamed = session.update(msg[:16]) + session.finalize(msg[16:])
        assert streamed == one_shot


class TestDecryptHoldbackTiming:
    """RFC `update()` docstring: for a padded (non-"none") DECRYPT session,
    feeding N aligned ciphertext blocks via `update()` yields N-1 blocks
    back -- the most recent complete block may carry padding and is held
    back until `finalize()` (mirrors tests/test_streaming.py's CBC
    coverage; ECB shares the engine's mode-agnostic padding/holdback
    implementation with CBC, per the RFC's "What it hides" section)."""

    def test_pkcs7_decrypt_update_withholds_final_block(self) -> None:
        key = TwofishKey(KEY_32)
        plaintext = bytes(range(35))  # pads out to 3 full blocks (48 bytes)
        ciphertext = key.ecb_encryptor(padding=Padding.PKCS7).finalize(plaintext)
        assert len(ciphertext) == 48  # 3 aligned blocks in

        session = key.ecb_decryptor(padding=Padding.PKCS7)
        update_out = session.update(ciphertext)
        assert len(update_out) == 32  # N-1 = 2 blocks; the 3rd is held back

        finalize_out = session.finalize()
        assert update_out + finalize_out == plaintext


class TestPaddingBehavior:
    """Every padding scheme round-trips through ECB sessions, matching the
    CBC one-shot behavior pinned in tests/test_one_shot_cbc.py (the engine
    implements padding once, mode-agnostically -- CBC and ECB share it by
    construction, per the RFC's "What it hides" section)."""

    @pytest.mark.parametrize("padding", ALL_PADDINGS)
    def test_round_trips_via_update_and_finalize(self, padding: Padding) -> None:
        key = TwofishKey(KEY_32)
        plaintext = bytes(range(32)) if padding == Padding.NONE else b"twenty-byte-long msg"
        ciphertext = key.ecb_encryptor(padding=padding).finalize(plaintext)
        recovered = key.ecb_decryptor(padding=padding).finalize(ciphertext)
        assert recovered == plaintext

    def test_none_padding_rejects_misaligned_data(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError, match=r"data length \(11\) is not a multiple of the block size \(16\)"
        ):
            key.ecb_encryptor(padding=Padding.NONE).finalize(b"not aligned")

    def test_decrypt_rejects_corrupted_pkcs7_padding(self) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.ecb_encryptor(padding=Padding.PKCS7).finalize(b"valid message")
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with pytest.raises(ValueError, match=r"decryption failed: invalid or corrupted ciphertext"):
            key.ecb_decryptor(padding=Padding.PKCS7).finalize(corrupted)

    def test_decrypt_rejects_ciphertext_shorter_than_one_block(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"decryption failed: invalid or corrupted ciphertext"):
            key.ecb_decryptor(padding=Padding.PKCS7).finalize(b"short")


class TestEmptyMessageMatrix:
    """RFC Contracts: empty-message matrix, pinned by test (ECB shares the
    engine's mode-agnostic padding implementation with CBC)."""

    @pytest.mark.parametrize("padding", [Padding.PKCS7, Padding.ANSIX923, Padding.ISO7816])
    def test_padded_schemes_encrypt_empty_to_one_full_block(self, padding: Padding) -> None:
        ciphertext = TwofishKey(KEY_16).ecb_encryptor(padding=padding).finalize(b"")
        assert len(ciphertext) == 16

    @pytest.mark.parametrize("padding", [Padding.ZEROS, Padding.NONE])
    def test_zeros_and_none_encrypt_empty_to_empty(self, padding: Padding) -> None:
        ciphertext = TwofishKey(KEY_16).ecb_encryptor(padding=padding).finalize(b"")
        assert ciphertext == b""


class TestKnownAnswerVectors:
    """Official Twofish ECB KATs (RFC Testing Strategy: "Official Twofish
    KATs (128/192/256) via `ecb_encryptor(padding=Padding.NONE)`")."""

    def test_vector_128bit_key(self) -> None:
        key = bytes.fromhex("00000000000000000000000000000000")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("9F589F5CF6122C32B6BFEC2F2AE8C35A")

        ciphertext = TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(plaintext)
        assert ciphertext == expected

    def test_vector_192bit_key(self) -> None:
        key = bytes.fromhex("0123456789ABCDEFFEDCBA98765432100011223344556677")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("CFD1D2E5A9BE9CDF501F13B892BD2248")

        ciphertext = TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(plaintext)
        assert ciphertext == expected

    def test_vector_256bit_key(self) -> None:
        key = bytes.fromhex("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF")
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        expected = bytes.fromhex("37527BE0052334B89F0CFCCAE87CFA20")

        ciphertext = TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(plaintext)
        assert ciphertext == expected

    @pytest.mark.parametrize(
        "key",
        [
            bytes.fromhex("00000000000000000000000000000000"),
            bytes.fromhex("0123456789ABCDEFFEDCBA98765432100011223344556677"),
            bytes.fromhex("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF"),
        ],
    )
    def test_kats_decrypt_round_trip(self, key: bytes) -> None:
        plaintext = bytes.fromhex("00000000000000000000000000000000")
        new_key = TwofishKey(key)
        ciphertext = new_key.ecb_encryptor(padding=Padding.NONE).finalize(plaintext)
        recovered = new_key.ecb_decryptor(padding=Padding.NONE).finalize(ciphertext)
        assert recovered == plaintext


class TestRepr:
    """`__repr__` shows mode, direction, and session state -- never key
    material (RFC Contracts: `__repr__`). Session-state labels are
    "fresh"/"streaming"/"finalized" (src/engine.rs's `state_label`)."""

    def test_repr_shows_mode_and_direction(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        r = repr(session)
        assert "ecb" in r
        assert "encrypt" in r

    def test_repr_shows_fresh_state(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        assert "fresh" in repr(session)

    def test_repr_shows_streaming_state_after_update(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.update(bytes(16))
        assert "streaming" in repr(session)

    def test_repr_shows_finalized_state_after_finalize(self) -> None:
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        session.finalize(bytes(16))
        assert "finalized" in repr(session)

    def test_repr_never_shows_key_material(self) -> None:
        raw = bytes.fromhex("ab" * 32)
        session = TwofishKey(raw).ecb_encryptor(padding=Padding.NONE)
        r = repr(session)
        assert raw.hex() not in r
        assert "ab" * 8 not in r
