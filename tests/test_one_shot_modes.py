"""Tests for RFC 0001's remaining one-shot modes + mode/padding misuse.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 10 ("Remaining
modes + padding-rejection + 'ecb' string rejection"). Extends
`TwofishKey.encrypt`/`decrypt` (slice 8's CBC-only one-shot hot path) with
a `mode` parameter dispatching CTR/CFB/OFB through the engine -- the same
`_encrypt_raw`/`_decrypt_raw` -> `engine::Session` -> `close_out` path CBC
already uses (Contracts: engine unification).

Mode-string validation lives in exactly one place on the Rust side
(`parse_mode` in src/lib.rs), shared by `_encrypt_raw` and `_decrypt_raw`.
The RFC's Error catalog pins its exact wording:
`"invalid mode '<value>': expected one of 'cbc', 'ctr', 'cfb', 'ofb'"`.
The string `"ecb"` gets no special carve-out -- it is simply absent from
the valid set, rejected identically to any other unrecognized mode
(regression-tested explicitly below per the RFC's callout).

Padding semantics per the RFC Contracts' "Padding defaults & rejection"
bullet: CBC's `padding=None` means PKCS7 (unchanged from slice 8); the
three stream modes (ctr/cfb/ofb) reject *any* explicit `padding=` value --
including `Padding.NONE`/`"none"` -- while an omitted (`None`) `padding`
is accepted (no padding is ever applied to a stream mode). This rejection
message is not part of the RFC's normative Error catalog table (which is
silent on its exact wording), so it is pinned here as this implementation's
chosen string.

`mode` is not yet a parameter on any streaming factory -- `encryptor`/
`decryptor`/ECB factories remain out of scope (slices 11-12).
"""

import pytest
from oxifish import Mode, Padding, TwofishKey

KEY_16 = bytes(range(16))
KEY_24 = bytes(range(24))
KEY_32 = bytes(range(32))
IV = bytes(range(16, 32))

# RFC 0002 change 3: these were hand-enumerated literal lists, an
# independent (and driftable) encoding of the `Mode` enum's value set on
# top of the Rust match arms + error message. Both are now introspected
# from `Mode` itself -- `STREAM_MODES` stays an *exclusion* (not
# `list(Mode)`), since it's load-bearing for the padding-rejection tests
# below, which must never include CBC (the one mode padding IS allowed on).
STREAM_MODES = [m for m in Mode if m != Mode.CBC]
ALL_MODES = list(Mode)


class TestRoundTrip:
    """encrypt/decrypt round-trips per mode x key size (RFC slice 10)."""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    @pytest.mark.parametrize("key", [KEY_16, KEY_24, KEY_32])
    def test_round_trips_for_every_stream_mode_and_key_size(self, mode: Mode, key: bytes) -> None:
        key_obj = TwofishKey(key)
        plaintext = b"a message that is not block aligned!"
        ciphertext = key_obj.encrypt(plaintext, mode, iv=IV)
        assert key_obj.decrypt(ciphertext, mode, iv=IV) == plaintext

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_round_trips_for_empty_message(self, mode: Mode) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"", mode, iv=IV)
        assert ciphertext == b""
        assert key_obj.decrypt(ciphertext, mode, iv=IV) == b""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_round_trips_for_sub_block_message(self, mode: Mode) -> None:
        key_obj = TwofishKey(KEY_32)
        plaintext = b"short"
        ciphertext = key_obj.encrypt(plaintext, mode, iv=IV)
        assert key_obj.decrypt(ciphertext, mode, iv=IV) == plaintext

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_round_trips_for_multi_block_aligned_message(self, mode: Mode) -> None:
        key_obj = TwofishKey(KEY_32)
        plaintext = bytes(range(256)) * 2  # 512 bytes, 32 aligned blocks
        ciphertext = key_obj.encrypt(plaintext, mode, iv=IV)
        assert key_obj.decrypt(ciphertext, mode, iv=IV) == plaintext

    def test_mode_string_and_enum_member_are_interchangeable(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"interchangeable mode selector"
        via_enum = key_obj.encrypt(plaintext, Mode.CTR, iv=IV)
        via_string = key_obj.encrypt(plaintext, "ctr", iv=IV)
        assert via_enum == via_string


class TestDefaultModeIsCBC:
    """Omitting `mode` defaults to CBC (unchanged from slice 8)."""

    def test_omitted_mode_matches_explicit_cbc(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"default mode check"
        assert key_obj.encrypt(plaintext, iv=IV) == key_obj.encrypt(plaintext, Mode.CBC, iv=IV)

    def test_omitted_mode_decrypts_cbc_ciphertext(self) -> None:
        key_obj = TwofishKey(KEY_16)
        ciphertext = key_obj.encrypt(b"round trip", Mode.CBC, iv=IV)
        assert key_obj.decrypt(ciphertext, iv=IV) == b"round trip"


class TestCrossModeDifferentiation:
    """Different modes on the same key/iv/plaintext must not collide."""

    def test_stream_modes_produce_distinct_ciphertext(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"same plaintext, different mode!"
        outputs = {mode: key_obj.encrypt(plaintext, mode, iv=IV) for mode in STREAM_MODES}
        assert len({outputs[m] for m in STREAM_MODES}) == len(STREAM_MODES)

    def test_cbc_and_ctr_produce_distinct_ciphertext(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"sixteen-byte-msg"
        cbc_ct = key_obj.encrypt(plaintext, Mode.CBC, iv=IV, padding=Padding.NONE)
        ctr_ct = key_obj.encrypt(plaintext, Mode.CTR, iv=IV)
        assert cbc_ct != ctr_ct


class TestStreamModePaddingRejection:
    """RFC Contracts: "Padding defaults & rejection" -- stream modes reject
    *any* explicit `padding=`, including `"none"`; an omitted `padding`
    (`None`) is fine."""

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_omitted_padding_succeeds(self, mode: Mode) -> None:
        key_obj = TwofishKey(KEY_16)
        # No exception; padding=None (the default) applies no padding.
        ciphertext = key_obj.encrypt(b"no padding needed", mode, iv=IV)
        assert key_obj.decrypt(ciphertext, mode, iv=IV) == b"no padding needed"

    @pytest.mark.parametrize("mode", STREAM_MODES)
    @pytest.mark.parametrize(
        "padding",
        [Padding.NONE, "none", Padding.PKCS7, "pkcs7", Padding.ZEROS, "bogus"],
    )
    def test_encrypt_rejects_any_explicit_padding(self, mode: Mode, padding: Padding | str) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=rf"padding is not supported for mode '{mode.value}'",
        ):
            key_obj.encrypt(b"data", mode, iv=IV, padding=padding)

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_decrypt_rejects_any_explicit_padding(self, mode: Mode) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=rf"padding is not supported for mode '{mode.value}'",
        ):
            key_obj.decrypt(bytes(16), mode, iv=IV, padding=Padding.NONE)

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_explicit_padding_none_string_is_still_rejected(self, mode: Mode) -> None:
        # The RFC is explicit: passing the *string* "none" is an explicit
        # value and must be rejected -- only an *omitted* padding argument
        # (Python default None) is accepted.
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match="padding is not supported"):
            key_obj.encrypt(b"data", mode, iv=IV, padding="none")


class TestUnknownModeRejection:
    """RFC Error catalog: unrecognized mode strings, including the
    literal "ecb" (no special carve-out beyond being absent from the
    valid set)."""

    def test_encrypt_rejects_ecb_string_with_standard_unknown_mode_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'ecb': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key_obj.encrypt(b"data", "ecb", iv=IV)

    def test_decrypt_rejects_ecb_string_with_standard_unknown_mode_message(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'ecb': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key_obj.decrypt(bytes(16), "ecb", iv=IV)

    @pytest.mark.parametrize("bogus_mode", ["ECB", "Cbc", "bogus", "", "cbc "])
    def test_encrypt_rejects_other_unknown_mode_strings(self, bogus_mode: str) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=rf"invalid mode '{bogus_mode}': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key_obj.encrypt(b"data", bogus_mode, iv=IV)

    def test_decrypt_rejects_unknown_mode_string(self) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"invalid mode 'bogus': expected one of 'cbc', 'ctr', 'cfb', 'ofb'",
        ):
            key_obj.decrypt(bytes(16), "bogus", iv=IV)

    def test_mode_string_matching_is_case_sensitive_and_exact(self) -> None:
        # Mirrors the RFC Contracts' "Mode/Padding strings match exactly"
        # bullet: no trimming, no normalization.
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"invalid mode 'CTR'"):
            key_obj.encrypt(b"data", "CTR", iv=IV)


class TestIVHandlingPerMode:
    """Every mode's `iv` is a full 16-byte block (CTR: the initial counter
    block, per the RFC's CTR contract) -- uniform length validation."""

    @pytest.mark.parametrize("mode", ALL_MODES)
    @pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
    def test_encrypt_rejects_wrong_iv_length(self, mode: Mode, bad_len: int) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key_obj.encrypt(b"data", mode, iv=bytes(bad_len))

    @pytest.mark.parametrize("mode", ALL_MODES)
    @pytest.mark.parametrize("bad_len", [0, 1, 15, 17, 32])
    def test_decrypt_rejects_wrong_iv_length(self, mode: Mode, bad_len: int) -> None:
        key_obj = TwofishKey(KEY_16)
        with pytest.raises(ValueError, match=r"IV must be 16 bytes, got \d+"):
            key_obj.decrypt(bytes(16), mode, iv=bytes(bad_len))

    @pytest.mark.parametrize("mode", STREAM_MODES)
    def test_iv_reuse_across_calls_is_not_flagged(self, mode: Mode) -> None:
        # The new surface doesn't track IV consumption at the key level
        # (that's a session-level concern, later slices) -- reusing the
        # same iv across two one-shot calls with the same plaintext must
        # deterministically reproduce the same ciphertext (sanity check
        # that iv is actually wired through, not silently randomized).
        key_obj = TwofishKey(KEY_16)
        plaintext = b"deterministic given same key/iv"
        first = key_obj.encrypt(plaintext, mode, iv=IV)
        second = key_obj.encrypt(plaintext, mode, iv=IV)
        assert first == second

    def test_different_iv_changes_ctr_output(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"same key and plaintext, different iv counter"
        other_iv = bytes(range(31, 15, -1))
        assert len(other_iv) == 16
        assert other_iv != IV
        ct_a = key_obj.encrypt(plaintext, Mode.CTR, iv=IV)
        ct_b = key_obj.encrypt(plaintext, Mode.CTR, iv=other_iv)
        assert ct_a != ct_b

    def test_different_iv_changes_cfb_output(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"same key and plaintext, different iv feedback"
        other_iv = bytes(range(31, 15, -1))
        assert len(other_iv) == 16
        assert other_iv != IV
        ct_a = key_obj.encrypt(plaintext, Mode.CFB, iv=IV)
        ct_b = key_obj.encrypt(plaintext, Mode.CFB, iv=other_iv)
        assert ct_a != ct_b

    def test_different_iv_changes_ofb_output(self) -> None:
        key_obj = TwofishKey(KEY_16)
        plaintext = b"same key and plaintext, different iv keystream"
        other_iv = bytes(range(31, 15, -1))
        assert len(other_iv) == 16
        assert other_iv != IV
        ct_a = key_obj.encrypt(plaintext, Mode.OFB, iv=IV)
        ct_b = key_obj.encrypt(plaintext, Mode.OFB, iv=other_iv)
        assert ct_a != ct_b
