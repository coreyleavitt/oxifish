"""Tests for RFC 0003 slice 5: the `ctr_width` keyword.

RFC 0003 (docs/rfcs/0003-interop-breadth.md), Proposed Interface §3 ("CTR
counter width (`ctr_width` keyword)"). `ctr_width` narrows CTR's 16-byte
initial counter block to a NIST-style nonce||counter split (32/64/128
low-order bits increment, big-endian, wrapping through zero relative to
session start) -- the PyCryptodome `Counter`-convention split legacy
homegrown Twofish-CTR formats actually used (RFC Problem statement).

**Exhaustion is cargo-test-only** (RFC Testing Strategy): the
`2**ctr_width - 1`-block session limit needs `cipher::StreamCipherSeek` to
reach cheaply (a real `ctr_width=32` payload would need a 64 GiB
keystream); the cataloged exhaustion string is pinned at the Rust level
(`src/engine.rs`'s `ctr_width_32_one_shot_request_exceeding_remaining_
blocks_is_exhausted_not_panicking` and neighboring tests -- see the RFC
handoff for the full inventory). This module instead proves a
large-but-feasible `ctr_width=32` flow works, nowhere near that boundary,
plus everything else reachable from Python: the misuse-machine catalog
strings, the ECB-factory `TypeError` pin, the `ctr_width=128` regression
pin, wrap/divergence via near-boundary IVs, and a pure-Python reference
implementation cross-validated via Hypothesis.
"""

from __future__ import annotations

from typing import Literal

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from oxifish import Mode, Padding, TwofishKey

KEY = bytes(range(16))
IV = bytes(range(16, 32))


# ============================================================================
# Pure-Python reference split-counter CTR (RFC Testing Strategy: "reference
# implementations of ... split-counter CTR written into the test suite in
# pure Python over the blessed ECB idiom"), independent of src/engine.rs's
# `ctr`-crate-backed implementation.
# ============================================================================


def reference_ctr(key: bytes, iv: bytes, data: bytes, ctr_width: int) -> bytes:
    """PyCryptodome `Counter`-convention split CTR: the low `ctr_width`
    bits of the 16-byte initial counter block `iv` increment, big-endian,
    relative to the start of the stream, wrapping through zero; the
    remaining high-order "nonce" bytes never change. Built over
    `ecb_encryptor(padding=Padding.NONE)` (itself pinned by the official
    Twofish ECB KATs, the same blessed idiom the README's migration
    section documents) -- no code shared with `src/engine.rs` beyond the
    underlying block cipher.
    """
    width_bytes = ctr_width // 8
    modulus = 1 << ctr_width
    nonce, base = iv[: 16 - width_bytes], int.from_bytes(iv[16 - width_bytes :], "big")
    ecb = TwofishKey(key).ecb_encryptor(padding=Padding.NONE)
    out = bytearray()
    for block_index, start in enumerate(range(0, len(data), 16)):
        chunk = data[start : start + 16]
        counter = (base + block_index) % modulus
        counter_block = nonce + counter.to_bytes(width_bytes, "big")
        keystream = ecb.update(counter_block)
        out.extend(b ^ k for b, k in zip(chunk, keystream, strict=False))
    return bytes(out)


def _split_iv(width: int, nonce_and_high: bytes, counter: int) -> bytes:
    """Build a full 16-byte `iv` from `width`'s nonce portion (the high
    `16 - width // 8` bytes of `nonce_and_high`) plus an initial counter
    value -- the same shape `reference_ctr` and the real `ctr_width`
    keyword both interpret."""
    width_bytes = width // 8
    nonce = nonce_and_high[: 16 - width_bytes]
    return nonce + counter.to_bytes(width_bytes, "big")


class TestRegressionCtrWidth128:
    """`ctr_width=128` (the default) must reproduce plain `Mode.CTR`
    output byte-for-byte -- the RFC's "today's behavior is unchanged"
    claim, pinned here from the Python surface (cargo test pins the same
    claim at the engine level, independently)."""

    @pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 50])
    def test_ctr_width_128_matches_plain_ctr(self, length: int) -> None:
        key = TwofishKey(KEY)
        data = bytes(range(length))
        default = key.encrypt(data, Mode.CTR, iv=IV)
        explicit = key.encrypt(data, Mode.CTR, iv=IV, ctr_width=128)
        assert default == explicit
        assert explicit == reference_ctr(KEY, IV, data, 128)


class TestMisuseMachine:
    """Exact-string pins for both new catalog entries, reachable from
    every `ctr_width`-bearing entry point."""

    @pytest.mark.parametrize("ctr_width", [0, 7, 16, 33, 127, 2**64])
    def test_invalid_ctr_width_one_shot_encrypt(self, ctr_width: int) -> None:
        # Near-boundary values (0, 16, 33, 127) and a huge int (2**64), in
        # addition to the original 7 -- an out-of-catalog int must always
        # hit this ValueError, never overflow/wrap oddly at either extreme.
        key = TwofishKey(KEY)
        with pytest.raises(
            ValueError, match=rf"^invalid ctr_width {ctr_width}: expected one of 32, 64, 128$"
        ):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=ctr_width)  # type: ignore[call-overload]

    def test_invalid_ctr_width_one_shot_decrypt(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError, match=r"^invalid ctr_width 7: expected one of 32, 64, 128$"):
            key.decrypt(b"data", Mode.CTR, iv=IV, ctr_width=7)  # type: ignore[arg-type]

    def test_invalid_ctr_width_encryptor(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError, match=r"^invalid ctr_width 7: expected one of 32, 64, 128$"):
            key.encryptor(Mode.CTR, iv=IV, ctr_width=7)  # type: ignore[arg-type]

    def test_invalid_ctr_width_decryptor(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError, match=r"^invalid ctr_width 7: expected one of 32, 64, 128$"):
            key.decryptor(Mode.CTR, iv=IV, ctr_width=7)  # type: ignore[arg-type]

    @pytest.mark.parametrize("mode", [Mode.CBC, Mode.CFB, Mode.OFB])
    def test_ctr_width_rejected_for_every_non_ctr_mode(self, mode: Mode) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(
            ValueError,
            match=rf"^ctr_width is not supported for mode '{mode.value}': only mode 'ctr' "
            r"accepts the ctr_width argument$",
        ):
            key.encrypt(b"data", mode, iv=IV, ctr_width=64)

    def test_ctr_width_default_128_is_a_silent_no_op_on_non_ctr_modes(self) -> None:
        # ctr_width's default (128) is indistinguishable from omission at
        # the public signature (it has no `None` sentinel of its own, per
        # the RFC's pinned exact signature) -- passing it explicitly on a
        # non-CTR mode is therefore a documented no-op, not a rejection.
        key = TwofishKey(KEY)
        msg = bytes(range(16))
        with_default = key.encrypt(msg, Mode.CBC, iv=IV, padding=Padding.NONE)
        explicit_128 = key.encrypt(msg, Mode.CBC, iv=IV, padding=Padding.NONE, ctr_width=128)
        assert with_default == explicit_128


class TestCtrWidthTypeGuard:
    """Non-int `ctr_width` raises `TypeError` naming the actual type --
    distinct from the cataloged `ValueError` for out-of-catalog *int*
    values (RFC 0003 §3). Without this guard, `ctr_width=32.0` passes the
    `in (32, 64, 128)` catalog check by `==` and falls through to the raw
    PyO3 layer's generic, uncataloged `TypeError`; `ctr_width="64"` fails
    the catalog check in a way that misleadingly renders as an
    out-of-catalog *value* rejection ("invalid ctr_width 64: expected one
    of 32, 64, 128") rather than a type error."""

    @pytest.mark.parametrize(("value", "type_name"), [(32.0, "float"), ("64", "str")])
    def test_non_int_ctr_width_type_error_message(self, value: object, type_name: str) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=rf"^ctr_width must be an int, got {type_name}$"):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=value)  # type: ignore[call-overload]

    def test_non_int_ctr_width_one_shot_encrypt(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got float$"):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=32.0)  # type: ignore[call-overload]

    def test_non_int_ctr_width_one_shot_decrypt(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got float$"):
            key.decrypt(b"data", Mode.CTR, iv=IV, ctr_width=32.0)  # type: ignore[arg-type]

    def test_non_int_ctr_width_encryptor(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got float$"):
            key.encryptor(Mode.CTR, iv=IV, ctr_width=32.0)  # type: ignore[arg-type]

    def test_non_int_ctr_width_decryptor(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got float$"):
            key.decryptor(Mode.CTR, iv=IV, ctr_width=32.0)  # type: ignore[arg-type]

    def test_type_guard_precedes_the_non_ctr_mode_check(self) -> None:
        # ctr_width's type check runs before the mode-mismatch rejection --
        # `ctr_width="64"` on a non-CTR mode is a TypeError, not the
        # ValueError catalog row for ctr_width on a mismatched mode (RFC
        # 0003 §3): the type check wins.
        key = TwofishKey(KEY)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got str$"):
            key.encrypt(b"data", Mode.CBC, iv=IV, ctr_width="64")  # type: ignore[call-overload]

    def test_bool_ctr_width_falls_through_to_the_value_catalog(self) -> None:
        # isinstance(True, int) is True -- bool is deliberately not
        # special-cased, so it falls through to the existing catalog
        # ValueError. Canonicalization (`int.__index__`) renders every int
        # subclass -- bool included -- as its true payload, so True now
        # renders as 1, not as the literal "True".
        key = TwofishKey(KEY)
        with pytest.raises(ValueError, match=r"^invalid ctr_width 1: expected one of 32, 64, 128$"):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=True)  # type: ignore[call-overload]


class _LyingCtrWidth(int):
    """An `int` subclass whose comparisons unconditionally lie ("equal to
    everything"), independent of its true C-level (`PyLong`) payload --
    the exact vector code-review finding L12 closes: `isinstance(x, int)`
    alone does not guarantee `x`'s comparisons agree with `x`'s actual
    stored value. `int.__eq__`/`__ne__` are overridden (not `__lt__`/
    `__ge__`) because `_validate_ctr_width`'s vulnerable check is
    membership (`ctr_width not in _CTR_WIDTHS`, which compares by `==`),
    not a range comparison.
    """

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return int.__hash__(self)


class TestLyingIntSubclassCanonicalization:
    """Code-review finding L12: a `ctr_width` whose `__eq__` lies must
    never bypass the catalog check or reach the raw PyO3 layer under a
    payload the facade never actually validated. Before the fix, this
    `_LyingCtrWidth(999)` instance compares equal to every catalog member
    (`999 in (32, 64, 128)` lies `True`), so `_validate_ctr_width` raises
    nothing at all and `_resolve_ctr_width` also lies `ctr_width == 128`
    is `True`, silently collapsing the out-of-catalog payload onto the
    128-bit default -- a silent misuse bypass, not merely a wrong
    exception type. `int.__index__` canonicalization fixes this: the
    catalog check and the rendered message both see the true payload 999.

    The second test pins the downstream half (review finding H1, round 4):
    canonicalization inside the validator alone is not enough --
    `_resolve_ctr_width` must consume the validator's canonicalized return
    value, because re-comparing the caller's ORIGINAL object (`== 128`)
    hands a lying `__eq__` a second bypass even for an in-catalog payload
    that passed validation legitimately.
    """

    def test_lying_ctr_width_raises_the_cataloged_value_error_with_the_true_payload(self) -> None:
        key = TwofishKey(KEY)
        lying = _LyingCtrWidth(999)
        with pytest.raises(
            ValueError, match=r"^invalid ctr_width 999: expected one of 32, 64, 128$"
        ):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=lying)  # type: ignore[call-overload]

    def test_lying_in_catalog_ctr_width_still_encrypts_at_its_true_width(self) -> None:
        # Code-review finding H1 (round 4, L12 fix-incompleteness):
        # `_resolve_ctr_width` must collapse onto the raw layer's `None`
        # sentinel by comparing the CANONICALIZED value against 128 -- never
        # the caller's original object. A `_LyingCtrWidth(32)` passes
        # validation (true payload 32 is in the catalog), but its lying
        # `__eq__` answers `True` to `== 128`; re-comparing the original
        # object would silently widen the caller's validated 32-bit split
        # to the full 128-bit counter -- no exception, wrong ciphertext.
        key = TwofishKey(KEY)
        iv = b"\xff" * 16  # widths diverge at block 1 under an all-0xFF IV
        data = b"\x00" * 32
        lying = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=_LyingCtrWidth(32))  # type: ignore[call-overload]
        honest = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=32)
        default = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=128)
        assert honest != default  # the IV/payload choice genuinely separates the widths
        assert lying == honest
        assert lying != default


class TestEcbFactoryTypeErrorPin:
    """ECB factories get no `ctr_width` parameter at all -- the natural
    `TypeError` is the pinned behavior (RFC §3)."""

    def test_ecb_encryptor_rejects_ctr_width(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError):
            key.ecb_encryptor(padding=Padding.NONE, ctr_width=64)  # type: ignore[call-arg]

    def test_ecb_decryptor_rejects_ctr_width(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(TypeError):
            key.ecb_decryptor(padding=Padding.NONE, ctr_width=64)  # type: ignore[call-arg]


class TestDivergenceAndWrap:
    """Widths 32/64/128 diverge past the boundary their own low bits
    define; wrap-through-zero matches the reference implementation, via
    near-boundary IVs (RFC Testing Strategy) -- never a multi-gigabyte
    payload."""

    def test_widths_diverge_past_the_first_block(self) -> None:
        # All-0xFF: `+1` wraps each width's own low bits through zero
        # independently, so block 1 genuinely differs across widths. A
        # "generic" IV like uniform 0x77 is a trap: incrementing a byte
        # that isn't already 0xFF never carries into the next byte, so
        # widths 32 and 64 can coincidentally produce the *same* block 1
        # (cargo test src/engine.rs::ctr_widths_32_64_128_diverge_past_
        # the_first_block hit exactly this before switching to 0xFF).
        key = TwofishKey(KEY)
        iv = bytes([0xFF] * 16)
        data = bytes(32)  # 2 blocks
        ct32 = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=32)
        ct64 = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=64)
        ct128 = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=128)

        assert ct32[:16] == ct64[:16] == ct128[:16], "block 0 is `iv` itself for every width"
        assert ct32[16:] != ct64[16:], "width 32 vs 64 must diverge at block 1"
        assert ct64[16:] != ct128[16:], "width 64 vs 128 must diverge at block 1"
        assert ct32[16:] != ct128[16:], "width 32 vs 128 must diverge at block 1"

    @pytest.mark.parametrize("width", [32, 64])
    def test_low_bits_wrap_through_zero_matching_the_reference(
        self, width: Literal[32, 64]
    ) -> None:
        key = TwofishKey(KEY)
        nonce_and_high = bytes([0x22] * 16)
        iv = _split_iv(width, nonce_and_high, (1 << width) - 2)  # 2 blocks from the wrap
        data = bytes(48)  # 3 blocks: crosses the wrap boundary

        ciphertext = key.encrypt(data, Mode.CTR, iv=iv, ctr_width=width)
        assert ciphertext == reference_ctr(KEY, iv, data, width)
        assert key.decrypt(ciphertext, Mode.CTR, iv=iv, ctr_width=width) == data


def _ctr_key_strategy() -> st.SearchStrategy[bytes]:
    return st.sampled_from([16, 24, 32]).flatmap(lambda n: st.binary(min_size=n, max_size=n))


class TestCrossValidationAgainstPureReference:
    """`TwofishKey.encrypt`/`.decrypt` (`Mode.CTR`) vs. `reference_ctr`,
    over random keys/IVs/lengths, for every width -- including wrap cases
    via near-boundary initial counters, not multi-gigabyte payloads."""

    @pytest.mark.parametrize("width", [32, 64, 128])
    @given(
        key=_ctr_key_strategy(),
        nonce_and_high=st.binary(min_size=16, max_size=16),
        counter_offset=st.integers(min_value=-4, max_value=4),
        data=st.binary(max_size=80),
    )
    @settings(max_examples=15, deadline=None)
    def test_encrypt_matches_reference_and_round_trips(
        self,
        width: Literal[32, 64, 128],
        key: bytes,
        nonce_and_high: bytes,
        counter_offset: int,
        data: bytes,
    ) -> None:
        # `counter_offset` mod 2**width biases some examples toward 0 and
        # some toward 2**width - 1 -- i.e. right up against the wrap
        # boundary from both sides -- without ever requesting enough
        # blocks to actually exhaust the stream (exhaustion itself is
        # cargo-test-only; see the module docstring).
        counter = counter_offset % (1 << width)
        iv = _split_iv(width, nonce_and_high, counter)

        tf_key = TwofishKey(key)
        ciphertext = tf_key.encrypt(data, Mode.CTR, iv=iv, ctr_width=width)

        assert len(ciphertext) == len(data)
        assert ciphertext == reference_ctr(key, iv, data, width)
        assert tf_key.decrypt(ciphertext, Mode.CTR, iv=iv, ctr_width=width) == data


class TestLargeButFeasibleCtrWidth32:
    """`ctr_width=32` supports real, large-but-cheap payloads far below
    its 64 GiB exhaustion boundary -- the only exhaustion-adjacent thing
    reachable from Python (see the module docstring)."""

    def test_multi_block_payload_round_trips(self) -> None:
        key = TwofishKey(KEY)
        # 1 MiB: 65536 blocks, nowhere near 2**32 - 1 -- cheap in CI, but
        # far larger than every other test in this module.
        data = bytes(range(256)) * (1024 * 1024 // 256)
        ciphertext = key.encrypt(data, Mode.CTR, iv=IV, ctr_width=32)
        assert key.decrypt(ciphertext, Mode.CTR, iv=IV, ctr_width=32) == data
