"""Tests for RFC 0003 slice 4: the `TwofishXTS` Python surface.

RFC 0003 (docs/rfcs/0003-interop-breadth.md), Proposed Interface §2
("XTS (`TwofishXTS`)"). `TwofishXTS` wraps the in-repo `XtsCipher<Twofish>`
engine (`src/xts.rs`, slice 3, already pinned against the IEEE 1619 Annex B
vectors and cross-validated bidirectionally against the `xts-mode` crate in
cargo tests) behind the `TwofishKey` two-layer pattern: a single
concatenated `key1 || key2` buffer, a keyword-only `tweak` (the data-unit
number, range-validated in this Python facade so an out-of-range value
raises `ValueError`, never PyO3's generic `OverflowError`), and no IV/
padding concept at all -- ciphertext stealing handles non-block-multiple
data units instead.

**Layered correctness argument (RFC Testing Strategy)**: the block
primitive is proven by the official Twofish ECB KATs (existing suite); the
Rust XTS engine is proven by the IEEE 1619 vectors plus bidirectional
`xts-mode` cross-validation (cargo tests, slice 3); this module adds the
third leg -- an independent, pure-Python XTS reference implementation
built *over* the blessed `ecb_encryptor/ecb_decryptor(padding=Padding.NONE)`
idiom (itself pinned by the official ECB KATs) -- so `TwofishXTS` is
cross-validated against a reimplementation with no code in common with
`src/xts.rs` beyond the underlying block cipher.

A VeraCrypt golden-volume fixture (the Testing Strategy's primary
Twofish-XTS *interop* proof, attempted first per this slice's brief) is
tracked separately -- see the handoff doc for the outcome.
"""

from __future__ import annotations

import copy
import pickle
import threading
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from oxifish import Padding, TwofishKey, TwofishXTS

MIN_DATA_UNIT_BYTES = 16
MAX_DATA_UNIT_BYTES = (1 << 20) * 16  # IEEE 1619's 2**20-block bound: 16 MiB


def _xts_key(total: int) -> bytes:
    """A valid, always-unequal-halves XTS key of `total` bytes (32/48/64).

    `key1`/`key2` are drawn from disjoint byte ranges so they can never
    collide regardless of `total`.
    """
    half = total // 2
    key1 = bytes(range(half))
    key2 = bytes(range(200, 200 + half))
    return key1 + key2


# ============================================================================
# Pure-Python reference XTS (RFC Testing Strategy: "reference
# implementations of XTS ... written into the test suite in pure Python
# over the blessed ECB idiom"), independent of src/xts.rs.
# ============================================================================


def _gf128_double(t: bytearray) -> None:
    """Multiply a 16-byte tweak block by GF(2**128)'s primitive element,
    in place -- LSB-first, matching `src/xts.rs::gf128_double`'s field
    convention (not shared code; this is the independent reimplementation)."""
    carry = 0
    for i in range(16):
        next_carry = t[i] >> 7
        t[i] = ((t[i] << 1) | carry) & 0xFF
        carry = next_carry
    if carry:
        t[0] ^= 0x87


def _xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _ecb_block_encrypt(key: bytes, block: bytes) -> bytes:
    return TwofishKey(key).ecb_encryptor(padding=Padding.NONE).finalize(block)


def _ecb_block_decrypt(key: bytes, block: bytes) -> bytes:
    return TwofishKey(key).ecb_decryptor(padding=Padding.NONE).finalize(block)


def _initial_tweak(key2: bytes, tweak: int) -> bytearray:
    tweak_block = tweak.to_bytes(16, "little")
    return bytearray(_ecb_block_encrypt(key2, tweak_block))


def reference_xts_encrypt(key: bytes, data: bytes, tweak: int) -> bytes:
    """Independent pure-Python XTS encrypt, IEEE 1619 §5.3.2 (with
    ciphertext stealing), built entirely over `ecb_encryptor(padding=
    Padding.NONE)` -- see this module's docstring re: the layered
    correctness argument this feeds."""
    half = len(key) // 2
    key1, key2 = key[:half], key[half:]
    t = _initial_tweak(key2, tweak)

    full_blocks, tail_len = divmod(len(data), 16)
    normal_blocks = full_blocks - (1 if tail_len else 0)
    out = bytearray()

    for j in range(normal_blocks):
        block = data[j * 16 : (j + 1) * 16]
        out += _xor16(_ecb_block_encrypt(key1, _xor16(block, bytes(t))), bytes(t))
        _gf128_double(t)

    if tail_len == 0:
        return bytes(out)

    last_full_start = normal_blocks * 16
    tail_start = last_full_start + 16
    p_last = data[last_full_start:tail_start]
    cc = _xor16(_ecb_block_encrypt(key1, _xor16(p_last, bytes(t))), bytes(t))

    pp = data[tail_start:] + cc[tail_len:]
    _gf128_double(t)
    c_full = _xor16(_ecb_block_encrypt(key1, _xor16(pp, bytes(t))), bytes(t))

    out += c_full
    out += cc[:tail_len]
    return bytes(out)


def reference_xts_decrypt(key: bytes, data: bytes, tweak: int) -> bytes:
    """Independent pure-Python XTS decrypt -- mirrors
    `reference_xts_encrypt`'s tweak/CTS handling in reverse."""
    half = len(key) // 2
    key1, key2 = key[:half], key[half:]
    t = _initial_tweak(key2, tweak)

    full_blocks, tail_len = divmod(len(data), 16)
    normal_blocks = full_blocks - (1 if tail_len else 0)
    out = bytearray()

    for j in range(normal_blocks):
        block = data[j * 16 : (j + 1) * 16]
        out += _xor16(_ecb_block_decrypt(key1, _xor16(block, bytes(t))), bytes(t))
        _gf128_double(t)

    if tail_len == 0:
        return bytes(out)

    last_full_start = normal_blocks * 16
    short_start = last_full_start + 16
    t_next = bytearray(t)
    _gf128_double(t_next)

    c_full = data[last_full_start:short_start]
    pp = _xor16(_ecb_block_decrypt(key1, _xor16(c_full, bytes(t_next))), bytes(t_next))

    cc = data[short_start:] + pp[tail_len:]
    p_last = _xor16(_ecb_block_decrypt(key1, _xor16(cc, bytes(t))), bytes(t))

    out += p_last
    out += pp[:tail_len]
    return bytes(out)


class TestReferenceImplementationSelfConsistency:
    """The reference implementation round-trips on its own, for every CTS
    residue -- proven before it is trusted as an oracle below."""

    @pytest.mark.parametrize("residue", range(16))
    def test_round_trips_for_every_cts_residue(self, residue: int) -> None:
        key = _xts_key(32)
        length = 16 + residue  # one full block plus the residue
        plaintext = bytes(range(length % 256)) if length <= 256 else bytes(length)
        ciphertext = reference_xts_encrypt(key, plaintext, tweak=99)
        assert len(ciphertext) == length
        assert reference_xts_decrypt(key, ciphertext, tweak=99) == plaintext


# ============================================================================
# Construction: key coercion, length validation, equal-halves rejection.
# ============================================================================


class TestConstruction:
    @pytest.mark.parametrize("total", [32, 48, 64])
    def test_accepts_every_valid_total_key_length(self, total: int) -> None:
        xts = TwofishXTS(_xts_key(total))
        assert xts.key_size == total

    @pytest.mark.parametrize("total", [0, 1, 16, 31, 33, 47, 49, 63, 65, 96, 128])
    def test_rejects_every_invalid_total_key_length(self, total: int) -> None:
        with pytest.raises(
            ValueError,
            match=r"^XTS key must be 32, 48, or 64 bytes \(two 128, 192, or 256 bit halves\), "
            rf"got {total} bytes$",
        ):
            TwofishXTS(bytes(total))

    @pytest.mark.parametrize("total", [32, 48, 64])
    def test_rejects_equal_halves(self, total: int) -> None:
        half = total // 2
        key = bytes(range(half)) * 2
        with pytest.raises(ValueError, match=r"^XTS key halves must not be equal$"):
            TwofishXTS(key)

    def test_accepts_bytearray(self) -> None:
        xts = TwofishXTS(bytearray(_xts_key(32)))
        assert xts.key_size == 32

    def test_accepts_memoryview(self) -> None:
        xts = TwofishXTS(memoryview(_xts_key(32)))
        assert xts.key_size == 32


class TestConstructionRejectsWrongTypes:
    """Mirrors tests/test_key.py::TestTwofishKeyRejectsWrongTypes: `str`/
    `int` must raise a domain `TypeError`, and `int` must never silently
    succeed as an all-zero key (`bytes(64) == 64 zero bytes` is valid
    Python)."""

    def test_rejects_str_key_with_domain_message(self) -> None:
        with pytest.raises(TypeError, match=r"key must be a bytes-like object.*got str"):
            TwofishXTS("x" * 32)  # type: ignore[arg-type]

    def test_rejects_int_key_with_domain_message(self) -> None:
        with pytest.raises(TypeError, match=r"key must be a bytes-like object.*got int"):
            TwofishXTS(32)  # type: ignore[arg-type]


class TestKeySize:
    """`key_size` reports TOTAL key bytes (32/48/64), matching
    `TwofishKey.key_size`'s total-bytes meaning (RFC §2 ergonomics note) --
    not bytes-per-half."""

    @pytest.mark.parametrize("total", [32, 48, 64])
    def test_key_size_is_total_not_per_half(self, total: int) -> None:
        assert TwofishXTS(_xts_key(total)).key_size == total


# ============================================================================
# Data-unit length validation (misuse machine): the engine's cataloged
# ValueError, forwarded verbatim by the facade.
# ============================================================================


class TestDataUnitLengthValidation:
    @pytest.mark.parametrize("n", [0, 1, 15])
    def test_rejects_data_shorter_than_one_block(self, n: int) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(
            ValueError, match=rf"^XTS data unit must be 16 to 16777216 bytes, got {n} bytes$"
        ):
            xts.encrypt(bytes(n), tweak=0)

    def test_rejects_data_longer_than_the_2_pow_20_block_bound(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        n = MAX_DATA_UNIT_BYTES + 1
        with pytest.raises(
            ValueError, match=rf"^XTS data unit must be 16 to 16777216 bytes, got {n} bytes$"
        ):
            xts.encrypt(bytes(n), tweak=0)

    def test_decrypt_rejects_the_same_way(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(
            ValueError, match=r"^XTS data unit must be 16 to 16777216 bytes, got 5 bytes$"
        ):
            xts.decrypt(bytes(5), tweak=0)

    def test_accepts_the_minimum_boundary(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        ciphertext = xts.encrypt(bytes(MIN_DATA_UNIT_BYTES), tweak=0)
        assert len(ciphertext) == MIN_DATA_UNIT_BYTES

    def test_accepts_the_maximum_boundary(self) -> None:
        # The exact-16-MiB (2**20 blocks) ACCEPT boundary: MAX_DATA_UNIT_BYTES
        # itself must succeed, not just reject MAX + 1 (above) -- this was
        # previously only proven at the Rust layer (src/xts.rs cargo test),
        # never through the public Python API. Deliberately the only
        # large-payload test in this module (~20-25s at this cipher's
        # throughput); a repeating pattern keeps construction cheap.
        xts = TwofishXTS(_xts_key(32))
        plaintext = (bytes(range(256)) * (MAX_DATA_UNIT_BYTES // 256))[:MAX_DATA_UNIT_BYTES]
        ciphertext = xts.encrypt(plaintext, tweak=0)
        assert len(ciphertext) == MAX_DATA_UNIT_BYTES
        assert xts.decrypt(ciphertext, tweak=0) == plaintext


class TestNonBufferDataInputsRejected:
    def test_encrypt_rejects_str_data_with_domain_message(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got str"):
            xts.encrypt("not bytes", tweak=0)  # type: ignore[arg-type]

    def test_encrypt_rejects_int_data_with_domain_message(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got int"):
            xts.encrypt(16, tweak=0)  # type: ignore[arg-type]

    def test_decrypt_rejects_str_data_with_domain_message(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=r"data must be a bytes-like object.*got str"):
            xts.decrypt("not bytes", tweak=0)  # type: ignore[arg-type]


# ============================================================================
# Tweak validation: range 0 <= tweak < 2**128, ValueError never OverflowError.
# ============================================================================


class TestTweakValidation:
    def test_zero_is_accepted(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        ciphertext = xts.encrypt(bytes(16), tweak=0)
        assert xts.decrypt(ciphertext, tweak=0) == bytes(16)

    def test_two_pow_128_minus_1_is_accepted(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        tweak = 2**128 - 1
        ciphertext = xts.encrypt(bytes(16), tweak=tweak)
        assert xts.decrypt(ciphertext, tweak=tweak) == bytes(16)

    def test_negative_one_is_rejected_as_value_error_not_overflow_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(
            ValueError,
            match=r"^tweak must be a non-negative integer less than 2\*\*128, got -1$",
        ):
            xts.encrypt(bytes(16), tweak=-1)

    def test_two_pow_128_is_rejected_as_value_error_not_overflow_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        tweak = 2**128
        with pytest.raises(
            ValueError,
            match=rf"^tweak must be a non-negative integer less than 2\*\*128, got {tweak}$",
        ):
            xts.encrypt(bytes(16), tweak=tweak)

    def test_decrypt_validates_tweak_the_same_way(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(ValueError, match=r"^tweak must be a non-negative integer"):
            xts.decrypt(bytes(16), tweak=-1)

    def test_tweak_is_keyword_only(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError):
            xts.encrypt(bytes(16), 0)  # type: ignore[misc]


class TestTweakTypeGuard:
    """Non-int `tweak` raises `TypeError` naming the actual type -- distinct
    from the cataloged `ValueError` for out-of-range *int* values (RFC 0003
    §2). Without this guard, a non-int `tweak` (`str`/`float`) fails the
    `isinstance` check and previously fell straight into the range branch's
    `ValueError`, misleadingly rendering as an out-of-range *value*
    rejection ("tweak must be a non-negative integer less than 2**128, got
    0") rather than a type error."""

    @pytest.mark.parametrize(("value", "type_name"), [(0.0, "float"), ("0", "str")])
    def test_non_int_tweak_type_error_message(self, value: object, type_name: str) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=rf"^tweak must be an int, got {type_name}$"):
            xts.encrypt(bytes(16), tweak=value)  # type: ignore[arg-type]

    def test_non_int_tweak_encrypt(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=r"^tweak must be an int, got float$"):
            xts.encrypt(bytes(16), tweak=0.0)  # type: ignore[arg-type]

    def test_non_int_tweak_decrypt(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError, match=r"^tweak must be an int, got float$"):
            xts.decrypt(bytes(16), tweak=0.0)  # type: ignore[arg-type]

    def test_bool_tweak_falls_through_to_the_range_check_as_one(self) -> None:
        # isinstance(True, int) is True -- bool is deliberately not
        # special-cased, so it passes the type guard and then the range
        # check as 1, round-tripping like any other in-range int tweak
        # (unlike ctr_width, where an out-of-catalog bool raises the
        # ValueError catalog row; tweak=True is simply the in-range int 1).
        xts = TwofishXTS(_xts_key(32))
        ciphertext = xts.encrypt(bytes(16), tweak=True)
        assert ciphertext == xts.encrypt(bytes(16), tweak=1)
        assert xts.decrypt(ciphertext, tweak=True) == bytes(16)


class _LyingTweak(int):
    """An `int` subclass whose comparisons unconditionally lie "in range",
    independent of its true C-level (`PyLong`) payload -- the exact vector
    code-review finding L12 closes. `_validate_tweak`'s vulnerable check is
    a range comparison (`0 <= tweak < 2**128`), so `__ge__`/`__lt__` (the
    operators that range check actually dispatches to, since `tweak`'s
    type is a subclass of `int` and overrides the reflected `__ge__` for
    `0 <= tweak`) are overridden here, not `__eq__`.
    """

    def __ge__(self, other: object) -> bool:
        return True

    def __lt__(self, other: object) -> bool:
        return True


class TestLyingIntSubclassCanonicalization:
    """Code-review finding L12: a `tweak` whose comparisons lie must never
    reach the raw PyO3 `u128` boundary under a payload the facade never
    actually range-checked. Before the fix, `_LyingTweak(-1)` claims
    `0 <= tweak < 2**128` via lying `__ge__`/`__lt__`, so `_validate_tweak`
    lets the negative payload through and PyO3's `u128` extraction raises
    a generic, uncataloged `OverflowError` instead -- violating the house
    rule that all errors are cataloged. `int.__index__` canonicalization
    fixes this: the range check and the Rust layer both see the same,
    true payload, and an out-of-range payload always raises the cataloged
    `ValueError`, never `OverflowError`.
    """

    def test_lying_tweak_raises_the_cataloged_value_error_never_overflow_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        lying = _LyingTweak(-1)
        with pytest.raises(
            ValueError,
            match=r"^tweak must be a non-negative integer less than 2\*\*128, got -1$",
        ):
            xts.encrypt(bytes(16), tweak=lying)


class TestTweakIEEEGeneralityLabeling:
    """RFC Testing Strategy: "tests above 2**64-1 labeled as IEEE-generality
    (VeraCrypt/dm-crypt interop lives in the 64-bit subset)". VeraCrypt and
    dm-crypt `plain64` only ever present tweaks below 2**64 (a 64-bit sector
    index); the values below exceed that and are accepted purely because
    IEEE 1619 defines the full 128-bit tweak space, not because any real
    caller needs them."""

    @pytest.mark.parametrize(
        "tweak", [2**64, 2**64 + 1, 2**100, 2**128 - 1], ids=["2**64", "2**64+1", "2**100", "max"]
    )
    def test_ieee_generality_tweak_above_2_pow_64_round_trips(self, tweak: int) -> None:
        xts = TwofishXTS(_xts_key(32))
        plaintext = bytes(range(37))
        ciphertext = xts.encrypt(plaintext, tweak=tweak)
        assert xts.decrypt(ciphertext, tweak=tweak) == plaintext

    def test_a_64_bit_subset_tweak_differs_from_an_ieee_generality_tweak(self) -> None:
        # Distinct tweaks must produce distinct ciphertext regardless of
        # which region (VeraCrypt/dm-crypt-reachable vs. IEEE-generality
        # only) they fall in -- a tweak silently truncated to 64 bits would
        # collapse these two.
        xts = TwofishXTS(_xts_key(32))
        plaintext = bytes(range(16))
        real_world_tweak = 2**63  # within the 64-bit subset real formats use
        ieee_only_tweak = 2**64  # first value outside that subset
        assert xts.encrypt(plaintext, tweak=real_world_tweak) != xts.encrypt(
            plaintext, tweak=ieee_only_tweak
        )


# ============================================================================
# Contracts: repr, one-shot-only surface, identity equality, pickle/copy,
# GIL soundness.
# ============================================================================


class TestRepr:
    @pytest.mark.parametrize("total", [32, 48, 64])
    def test_repr_shows_key_size(self, total: int) -> None:
        r = repr(TwofishXTS(_xts_key(total)))
        assert "TwofishXTS" in r
        assert f"key_size={total}" in r

    def test_repr_matches_the_rfcs_literal_format(self) -> None:
        # Code-review finding L4: unified onto TwofishKey's angle-bracket
        # repr style (bytes unit is unchanged -- only the bracket style
        # moved from parens to angle brackets, matching `<TwofishKey
        # key_size=256>`).
        assert repr(TwofishXTS(_xts_key(64))) == "<TwofishXTS key_size=64>"

    def test_repr_never_shows_key_material(self) -> None:
        key1 = bytes([0xAB]) * 16
        key2 = bytes([0xCD]) * 16
        xts = TwofishXTS(key1 + key2)
        r = repr(xts)
        assert "ab" not in r.lower()
        assert "cd" not in r.lower()


class TestOneShotOnlySurface:
    """Code-review finding L6: `TwofishXTS` is one-shot-only by RFC 0003
    contract -- "is one-shot/random-access rather than streaming" (see the
    class docstring above; no `Mode`, no IV, no session concept at all).
    Nothing structurally pinned that it actually lacks the streaming
    session factories `TwofishKey` exposes; a session API appearing here
    should be a deliberate RFC change, not accidental drift (e.g. from a
    future refactor that shares more code with `TwofishKey`)."""

    FACTORY_NAMES = ("encryptor", "decryptor", "ecb_encryptor", "ecb_decryptor")

    @pytest.mark.parametrize("name", FACTORY_NAMES)
    def test_instance_has_no_session_factory_attribute(self, name: str) -> None:
        xts = TwofishXTS(_xts_key(32))
        assert not hasattr(xts, name)

    @pytest.mark.parametrize("name", FACTORY_NAMES)
    def test_class_has_no_session_factory_attribute(self, name: str) -> None:
        assert not hasattr(TwofishXTS, name)


class TestIdentityEqualityContract:
    """Code-review finding L5: `TwofishXTS` defines neither `__eq__` nor
    `__hash__`, so plain object identity applies -- and that IS the
    intended contract for key-material objects: value-based `__eq__`
    would require comparing secrets. Mirrors
    tests/test_misuse_and_concurrency.py::TestKeyIdentityEqualityContract.
    These are characterization pins, not new behavior."""

    def test_instance_equals_itself(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        assert xts == xts

    def test_two_instances_from_identical_key_bytes_are_not_equal(self) -> None:
        # Equality would require comparing secrets -- identity is correct.
        assert TwofishXTS(_xts_key(32)) != TwofishXTS(_xts_key(32))

    def test_two_instances_from_identical_key_bytes_have_independent_hashes(self) -> None:
        # Identity-based hashing: almost surely distinct across two
        # independently-allocated objects (not value-derived).
        assert hash(TwofishXTS(_xts_key(32))) != hash(TwofishXTS(_xts_key(32)))

    def test_hash_is_stable_across_calls(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        assert hash(xts) == hash(xts)


class TestPickleAndCopyGuards:
    """RFC §2: "Serialization posture matches RFC 0001's classes:
    unpicklable and non-copyable (TypeError)" -- mirrors
    tests/test_misuse_and_concurrency.py::TestPickleAndCopyGuards."""

    def test_pickle_raises_type_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError):
            pickle.dumps(xts)

    def test_copy_raises_type_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError):
            copy.copy(xts)

    def test_deepcopy_raises_type_error(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        with pytest.raises(TypeError):
            copy.deepcopy(xts)


class TestGilSoundness:
    """RFC §2 restates RFC 0001's GIL contract for this new class, not
    inherited by implication -- mirrors
    tests/test_misuse_and_concurrency.py::TestGilRelease's shape, ported to
    XTS's one-shot-only `encrypt`/`decrypt` (no session to stream through)."""

    def test_large_encrypt_releases_the_gil_for_another_thread_to_run(self) -> None:
        xts = TwofishXTS(_xts_key(32))
        payload = bytes(3_000_000 - (3_000_000 % 16))  # block-aligned, well under 16 MiB
        counter = [0]
        stop = threading.Event()

        def spin() -> None:
            while not stop.is_set():
                counter[0] += 1

        spinner = threading.Thread(target=spin)
        spinner.start()
        try:
            time.sleep(0.02)
            baseline_start = counter[0]
            time.sleep(0.05)
            baseline_rate_per_second = (counter[0] - baseline_start) / 0.05

            before = counter[0]
            xts.encrypt(payload, tweak=1)
            during = counter[0] - before
        finally:
            stop.set()
            spinner.join()

        assert during > baseline_rate_per_second * 0.001, (
            f"spinner advanced by {during} during encrypt() "
            f"(baseline {baseline_rate_per_second:.0f}/s) -- GIL may not have been released"
        )

    def test_bytearray_mutation_during_encrypt_does_not_corrupt_output(self) -> None:
        # Mirrors test_misuse_and_concurrency.py::TestGilRelease's
        # bytearray-mutation-during-session-update test: a never-mutated
        # tail proves no corruption bleeds into unrelated bytes; a
        # continuously-flipped first byte proves whatever value the
        # engine's GIL-held copy captured is *a* well-defined value, never
        # a torn/raced read.
        xts = TwofishXTS(_xts_key(32))
        tail = bytes(range(256)) * 4_000  # 1,024,000 never-mutated bytes
        first_byte = 0x11
        buf = bytearray([first_byte]) + bytearray(tail)  # 1,024,001 bytes: a valid data unit
        possible_first_bytes = {first_byte, first_byte ^ 0xFF}

        stop = threading.Event()

        def mutate() -> None:
            while not stop.is_set():
                buf[0] ^= 0xFF

        mutator = threading.Thread(target=mutate)
        mutator.start()
        try:
            ciphertext = xts.encrypt(buf, tweak=7)
        finally:
            stop.set()
            mutator.join()

        plaintext = xts.decrypt(ciphertext, tweak=7)
        assert plaintext[1:] == tail
        assert plaintext[0] in possible_first_bytes


# ============================================================================
# Hypothesis cross-validation against the pure-Python reference (RFC
# Testing Strategy: "In pytest: reference implementations of XTS ... run
# ... over the blessed ECB idiom"), plus round-trip and
# length-preservation properties, over every CTS tail residue.
# ============================================================================


def _xts_key_strategy() -> st.SearchStrategy[bytes]:
    def halves(half_len: int) -> st.SearchStrategy[bytes]:
        return (
            st.tuples(
                st.binary(min_size=half_len, max_size=half_len),
                st.binary(min_size=half_len, max_size=half_len),
            )
            .filter(lambda pair: pair[0] != pair[1])
            .map(lambda pair: pair[0] + pair[1])
        )

    return st.sampled_from([16, 24, 32]).flatmap(halves)


class TestCrossValidationAgainstPureReference:
    """`TwofishXTS` vs. `reference_xts_encrypt`/`reference_xts_decrypt`,
    over random keys/tweaks/lengths -- explicitly parametrized across every
    CTS tail residue (RFC Testing Strategy: "covering every CTS tail
    residue (len % 16 in 0..15)"), with Hypothesis fuzzing the rest."""

    @pytest.mark.parametrize("residue", range(16))
    @given(
        key=_xts_key_strategy(),
        blocks=st.integers(min_value=1, max_value=3),
        tweak=st.integers(min_value=0, max_value=2**128 - 1),
        data=st.data(),
    )
    @settings(max_examples=8, deadline=None)
    def test_encrypt_matches_reference_and_round_trips(
        self,
        residue: int,
        key: bytes,
        blocks: int,
        tweak: int,
        data: st.DataObject,
    ) -> None:
        length = blocks * 16 + residue
        plaintext = data.draw(st.binary(min_size=length, max_size=length), label="plaintext")

        xts = TwofishXTS(key)
        ciphertext = xts.encrypt(plaintext, tweak=tweak)

        assert len(ciphertext) == length  # length preservation (pinned property)
        assert ciphertext == reference_xts_encrypt(key, plaintext, tweak)
        assert xts.decrypt(ciphertext, tweak=tweak) == plaintext
        assert reference_xts_decrypt(key, ciphertext, tweak) == plaintext


class TestExports:
    def test_twofish_xts_is_exported(self) -> None:
        import oxifish

        assert hasattr(oxifish, "TwofishXTS")
        assert "TwofishXTS" in oxifish.__all__
