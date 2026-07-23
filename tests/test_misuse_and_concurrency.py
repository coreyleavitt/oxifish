"""Tests for RFC 0001's misuse machine, `DecryptionError` wiring, and GIL
release.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 15 ("Misuse
machine + DecryptionError + GIL release"). This is the slice's full scope
per the Slices section: "Error catalog implemented + all strings tested;
empty-message matrix; pickle/copy/repr guards; concurrency-race test; GIL
release with copy-before-release + the two threading tests."

**Scope notes (documented, not silent guesses):**

- The empty-message matrix (RFC Contracts) is already pinned by prior
  slices (tests/test_one_shot_cbc.py::TestEmptyMessageMatrix,
  tests/test_ecb.py::TestEmptyMessageMatrix) and by cargo test
  (src/engine.rs's `empty_message_*` tests) -- not re-duplicated here.
- Most error-catalog strings (unknown mode/padding, `padding="none"`
  misalignment, "session is already finalized") are already regression-
  tested across tests/test_one_shot_modes.py, tests/test_streaming.py, and
  tests/test_ecb.py. This module adds the two rows that were NOT
  previously reachable/testable: `DecryptionError` (inert until this
  slice wired it in src/lib.rs's `engine_err_to_py`) and the concurrent-
  access `RuntimeError`/`PyBorrowMutError` row (unreachable without a
  real GIL-release window, also new this slice) -- plus a consolidated
  `TestErrorCatalog` class that exercises one example of every catalog
  row from a single place, for auditability.
- **`DecryptionError` mechanism (reconciliation, documented):** slice 7
  originally pinned an *inert* `class DecryptionError(ValueError): ...`
  defined in `python/oxifish/__init__.py`. This slice instead defines it
  in Rust via `pyo3::create_exception!` and re-exports it from Python,
  because `TwofishSession` (returned directly from Rust, no Python
  wrapper) has no facade call site to translate a distinguishable Rust
  error into a Python-defined type the way `TwofishKey.decrypt` could --
  see the reconciliation note in `python/oxifish/__init__.py` and
  `src/lib.rs`. Observably, `oxifish.DecryptionError` is unchanged: an
  importable, catchable `ValueError` subclass.
- **GIL release:** `py.allow_threads`/`Python::detach` (PyO3 0.27
  deprecated the former name in favor of the latter; this crate uses
  `Python::detach`, the RFC's "release the GIL around the pure-Rust
  transform" intent under its current name) now wraps the engine
  transform in `TwofishKey._encrypt_raw`/`_decrypt_raw` and
  `TwofishSession.update`/`finalize`, over an owned copy made while the
  GIL was still held (RFC Concurrency contract). The two RFC-mandated
  threading tests -- "a second Python thread demonstrably runs... while a
  large `encrypt()` is in flight" and "a `bytearray`-mutation-during-
  encrypt test proving copy-before-release" -- plus a concurrent-one-shot
  correctness test and the concurrency-race test all live in
  `TestGilRelease`/`TestConcurrentSessionAccess` below.
"""

from __future__ import annotations

import copy
import pickle
import threading
import time

import pytest
from oxifish import DecryptionError, Mode, Padding, TwofishKey, TwofishSession, TwofishXTS

KEY_16 = bytes(range(16))
IV = bytes(range(16, 32))


class TestDecryptionErrorWiring:
    """`DecryptionError` fires for padded-decrypt failures on both
    one-shot `decrypt` and `TwofishSession.finalize` -- never for a
    caller-side `padding="none"` alignment mistake."""

    def test_one_shot_decrypt_corrupted_padding_raises_decryption_error(self) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encrypt(b"valid message", iv=IV, padding=Padding.PKCS7)
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with pytest.raises(DecryptionError) as exc_info:
            key.decrypt(corrupted, iv=IV, padding=Padding.PKCS7)
        assert str(exc_info.value) == "decryption failed: invalid or corrupted ciphertext"

    def test_one_shot_decrypt_short_ciphertext_raises_decryption_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(DecryptionError):
            key.decrypt(b"short", iv=IV, padding=Padding.PKCS7)

    def test_cbc_session_finalize_corrupted_padding_raises_decryption_error(self) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encrypt(b"valid message", iv=IV, padding=Padding.PKCS7)
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        session = key.decryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        with pytest.raises(DecryptionError) as exc_info:
            session.finalize(corrupted)
        assert str(exc_info.value) == "decryption failed: invalid or corrupted ciphertext"

    def test_ecb_session_finalize_corrupted_padding_raises_decryption_error(self) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.ecb_encryptor(padding=Padding.PKCS7).finalize(b"valid message!!!")
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        session = key.ecb_decryptor(padding=Padding.PKCS7)
        with pytest.raises(DecryptionError):
            session.finalize(corrupted)

    def test_decryption_error_is_catchable_as_plain_value_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError):
            key.decrypt(b"short", iv=IV, padding=Padding.PKCS7)

    def test_padding_none_misalignment_is_plain_value_error_not_decryption_error(self) -> None:
        # CBC is the only mode where an explicit `padding=NONE` reaches the
        # alignment check at all -- stream modes (ctr/cfb/ofb) reject any
        # explicit `padding=` before that point (RFC Contracts: "Padding
        # defaults & rejection"), and ECB has no `decrypt()` one-shot.
        key = TwofishKey(KEY_16)
        with pytest.raises(ValueError) as exc_info:
            key.decrypt(b"not aligned", Mode.CBC, iv=IV, padding=Padding.NONE)
        assert not isinstance(exc_info.value, DecryptionError)

    def test_session_padding_none_misalignment_is_plain_value_error_not_decryption_error(
        self,
    ) -> None:
        key = TwofishKey(KEY_16)
        session = key.decryptor(Mode.CBC, iv=IV, padding=Padding.NONE)
        with pytest.raises(ValueError) as exc_info:
            session.finalize(b"not aligned")
        assert not isinstance(exc_info.value, DecryptionError)


class TestErrorCatalog:
    """One example of every RFC Error-catalog row, exercised from a single
    place for auditability. Exact wording is pinned more thoroughly
    elsewhere (see this module's docstring); this class is the map."""

    def test_padded_decrypt_failure(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            DecryptionError, match=r"^decryption failed: invalid or corrupted ciphertext$"
        ):
            key.decrypt(b"short", iv=IV, padding=Padding.PKCS7)

    def test_padding_none_misalignment(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError, match=r"^data length \(11\) is not a multiple of the block size \(16\)$"
        ):
            key.decrypt(b"not aligned", iv=IV, padding=Padding.NONE)

    def test_unknown_mode_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"^invalid mode 'bogus': expected one of 'cbc', 'ctr', 'cfb', 'ofb'$",
        ):
            key.encrypt(b"data", "bogus", iv=IV)

    def test_unknown_padding_string(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"^invalid padding 'bogus': expected one of "
            r"'pkcs7', 'none', 'iso7816', 'ansix923', 'zeros'$",
        ):
            key.encrypt(b"data", iv=IV, padding="bogus")

    def test_invalid_ctr_width(self) -> None:
        # RFC 0003 §3.
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError, match=r"^invalid ctr_width 99: expected one of 32, 64, 128$"
        ):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=99)  # type: ignore[call-overload]

    def test_non_int_ctr_width(self) -> None:
        # RFC 0003 §3: a non-int ctr_width is a TypeError, distinct from
        # the ValueError catalog row above for out-of-catalog *int* values.
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"^ctr_width must be an int, got float$"):
            key.encrypt(b"data", Mode.CTR, iv=IV, ctr_width=32.0)  # type: ignore[call-overload]

    def test_invalid_tweak(self) -> None:
        # RFC 0003 §2. Voice-parallel to test_invalid_ctr_width above; the
        # exact-string pin itself lives in
        # tests/test_xts.py::TestTweakValidation.
        xts = TwofishXTS(bytes(range(16)) + bytes(range(200, 216)))
        with pytest.raises(
            ValueError,
            match=r"^tweak must be a non-negative integer less than 2\*\*128, got -1$",
        ):
            xts.encrypt(b"data" * 4, tweak=-1)

    def test_non_int_tweak(self) -> None:
        # RFC 0003 §2: a non-int tweak is a TypeError, distinct from the
        # ValueError catalog row above for out-of-range *int* values.
        xts = TwofishXTS(bytes(range(16)) + bytes(range(200, 216)))
        with pytest.raises(TypeError, match=r"^tweak must be an int, got float$"):
            xts.encrypt(b"data" * 4, tweak=0.0)  # type: ignore[arg-type]

    def test_ctr_width_on_non_ctr_mode(self) -> None:
        # RFC 0003 §3: voice-parallel to the padding-with-stream-mode
        # rejection above.
        key = TwofishKey(KEY_16)
        with pytest.raises(
            ValueError,
            match=r"^ctr_width is not supported for mode 'cbc': only mode 'ctr' "
            r"accepts the ctr_width argument$",
        ):
            key.encrypt(b"data", Mode.CBC, iv=IV, ctr_width=64)

    def test_update_after_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        session.finalize(b"data")
        with pytest.raises(RuntimeError, match=r"^session is already finalized$"):
            session.update(b"more")

    def test_concurrent_access_is_a_distinct_runtime_error(self) -> None:
        # See TestConcurrentSessionAccess for the actual race; this just
        # pins that PyO3's PyBorrowMutError message is textually distinct
        # from the finalized-session RuntimeError above (RFC catalog:
        # "distinct from the finalized message, documented as such").
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        session.finalize(b"data")
        try:
            session.update(b"more")
        except RuntimeError as finalized_err:
            assert "already borrowed" not in str(finalized_err).lower()


class TestSessionIVWrongTypeCoercion:
    """Code-review finding 11: `str`/`int` inputs to `encryptor`/
    `decryptor`'s `iv` must raise a domain `TypeError` naming the
    parameter and what was received -- never a raw/confusing CPython
    error, and never (for `int`, since `bytes(int)` is valid Python)
    silently succeed as an all-zero IV."""

    def test_encryptor_rejects_str_iv_with_domain_message(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got str"):
            key.encryptor(Mode.CBC, iv="sixteen-byte-iv!")  # type: ignore[arg-type]

    def test_encryptor_rejects_int_iv_with_domain_message(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got int"):
            key.encryptor(Mode.CBC, iv=16)  # type: ignore[arg-type]

    def test_decryptor_rejects_str_iv_with_domain_message(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got str"):
            key.decryptor(Mode.CBC, iv="sixteen-byte-iv!")  # type: ignore[arg-type]

    def test_decryptor_rejects_int_iv_with_domain_message(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError, match=r"iv must be a bytes-like object.*got int"):
            key.decryptor(Mode.CBC, iv=16)  # type: ignore[arg-type]


class TestPickleAndCopyGuards:
    """RFC Contracts: `TwofishKey`/`TwofishSession` are unpicklable and
    non-copyable -- `pickle.dumps`, `copy.copy`, and `copy.deepcopy` all
    raise `TypeError`. PyO3 pyclasses have no pickle/copy support unless a
    crate explicitly opts in (via `__reduce__`/`__getstate__`/`__copy__`);
    this class regression-tests that oxifish does not."""

    def test_key_pickle_raises_type_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError):
            pickle.dumps(key)

    def test_key_copy_raises_type_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError):
            copy.copy(key)

    def test_key_deepcopy_raises_type_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError):
            copy.deepcopy(key)

    def test_session_pickle_raises_type_error(self) -> None:
        session = TwofishKey(KEY_16).encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        with pytest.raises(TypeError):
            pickle.dumps(session)

    def test_session_copy_raises_type_error(self) -> None:
        session = TwofishKey(KEY_16).encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        with pytest.raises(TypeError):
            copy.copy(session)

    def test_session_deepcopy_raises_type_error(self) -> None:
        session = TwofishKey(KEY_16).encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        with pytest.raises(TypeError):
            copy.deepcopy(session)

    def test_ecb_session_pickle_raises_type_error(self) -> None:
        # ECB sessions are a structurally distinct construction path
        # (borrowed Arc<Twofish> vs. an owned clone) -- worth covering
        # separately in case pickle support were ever added per-variant.
        session = TwofishKey(KEY_16).ecb_encryptor(padding=Padding.NONE)
        with pytest.raises(TypeError):
            pickle.dumps(session)


class TestKeyIdentityEqualityContract:
    """Code-review finding L5: `TwofishKey` defines neither `__eq__` nor
    `__hash__`, so plain object identity applies -- and that IS the
    intended contract for key-material objects: value-based `__eq__`
    would require comparing secrets (and would invite accidental
    "are these the same key?" checks that leak timing). These are
    characterization pins, not new behavior."""

    def test_instance_equals_itself(self) -> None:
        key = TwofishKey(KEY_16)
        assert key == key

    def test_two_instances_from_identical_key_bytes_are_not_equal(self) -> None:
        # Equality would require comparing secrets -- identity is correct.
        assert TwofishKey(KEY_16) != TwofishKey(KEY_16)

    def test_two_instances_from_identical_key_bytes_have_independent_hashes(self) -> None:
        # Identity-based hashing: almost surely distinct across two
        # independently-allocated objects (not value-derived).
        assert hash(TwofishKey(KEY_16)) != hash(TwofishKey(KEY_16))

    def test_hash_is_stable_across_calls(self) -> None:
        key = TwofishKey(KEY_16)
        assert hash(key) == hash(key)


class TestConcurrentSessionAccess:
    """RFC Concurrency contract: sessions are single-writer. Two threads
    calling `update`/`finalize` on the *same* `TwofishSession`
    concurrently must raise `RuntimeError` (PyO3's `PyBorrowMutError`,
    "Already borrowed") -- distinguishable from the finalized-session
    message. Only observable now that `Python::detach` (RFC:
    `py.allow_threads`) actually releases the GIL around the engine
    transform (RFC 0001 slice 15) -- a barrier/retry loop guards against
    the inherent scheduling-timing flakiness of a real race (RFC Testing
    Strategy: "regression-tested with a barrier/retry to avoid
    flakiness")."""

    def test_concurrent_update_calls_on_one_session_raise_runtime_error(self) -> None:
        key = TwofishKey(KEY_16)
        # A `threading.Barrier` synchronizes both threads to call update()
        # within microseconds of each other, so the overlap window only
        # needs to exceed thread-scheduling jitter, not encryption time --
        # 200KB (empirically 100% reproducible locally) keeps this fast.
        payload = bytes(200_000)

        caught: list[BaseException] = []
        for _ in range(15):
            session = key.encryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
            barrier = threading.Barrier(2)
            errors: list[BaseException] = []

            def call(
                session: TwofishSession = session,
                barrier: threading.Barrier = barrier,
                errors: list[BaseException] = errors,
            ) -> None:
                # Loop variables bound as defaults (not closed over) --
                # each thread below is started and joined within the same
                # iteration, before the next iteration rebinds them, but
                # default-binding avoids relying on that ordering.
                barrier.wait()
                try:
                    session.update(payload)
                except BaseException as exc:  # noqa: BLE001 -- must catch across the thread boundary
                    errors.append(exc)

            threads = [threading.Thread(target=call) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            if errors:
                caught = errors
                break

        assert caught, "never observed overlapping session access across 15 retries"
        (err,) = caught
        assert isinstance(err, RuntimeError)
        assert "already borrowed" in str(err).lower()
        assert "already finalized" not in str(err).lower()


class TestGilRelease:
    """RFC Concurrency contract + Testing Strategy's "GIL-release test":
    the engine transform runs with the GIL released (`Python::detach`),
    over an owned copy made while the GIL was still held. This class
    covers both RFC-named tests plus the "concurrent one-shots... (
    correctness under parallelism)" case named in the RFC's threading-
    tests bullet."""

    def test_large_encrypt_releases_the_gil_for_another_thread_to_run(self) -> None:
        key = TwofishKey(KEY_16)
        # Twofish (RustCrypto's generic, non-hardware-accelerated
        # implementation) runs at roughly a few MB/s -- large enough to
        # give the spinner thread a real window, without over-inflating
        # this test's wall time.
        payload = bytes(3_000_000)
        counter = [0]
        stop = threading.Event()

        def spin() -> None:
            while not stop.is_set():
                counter[0] += 1

        spinner = threading.Thread(target=spin)
        spinner.start()
        try:
            # Calibrate the spinner's free-running rate first, so the
            # threshold below is robust to hardware speed rather than a
            # magic constant.
            time.sleep(0.02)
            baseline_start = counter[0]
            time.sleep(0.05)
            baseline_rate_per_second = (counter[0] - baseline_start) / 0.05

            before = counter[0]
            key.encrypt(payload, iv=IV)
            during = counter[0] - before
        finally:
            stop.set()
            spinner.join()

        # If the GIL were held throughout encrypt() (no `Python::detach`),
        # `during` would be ~0: no Python bytecode from another thread can
        # run while a native call holds the GIL for its whole duration.
        # A released GIL lets the spinner accumulate a meaningful fraction
        # of what it would have done running freely for the same wall time.
        assert during > baseline_rate_per_second * 0.001, (
            f"spinner advanced by {during} during encrypt() "
            f"(baseline {baseline_rate_per_second:.0f}/s) -- GIL may not have been released"
        )

    def test_bytearray_mutation_during_session_update_does_not_corrupt_output(self) -> None:
        # A never-mutated tail proves no corruption bleeds into unrelated
        # bytes; a continuously-flipped first byte proves whatever value
        # the engine's copy captured is *a* well-defined value (one of the
        # two the mutator could have set), not garbage from a torn/raced
        # read -- the closest thing to an external oracle available for a
        # value whose exact capture instant we don't control.
        key = TwofishKey(KEY_16)
        tail = bytes(range(256)) * 4_000  # 1,024,000 never-mutated bytes
        first_byte = 0x11
        buf = bytearray([first_byte]) + bytearray(tail)
        possible_first_bytes = {first_byte, first_byte ^ 0xFF}

        stop = threading.Event()

        def mutate() -> None:
            while not stop.is_set():
                buf[0] ^= 0xFF

        mutator = threading.Thread(target=mutate)
        mutator.start()
        try:
            session = key.encryptor(Mode.CTR, iv=IV)
            ciphertext = session.update(buf) + session.finalize()
        finally:
            stop.set()
            mutator.join()

        dec_session = key.decryptor(Mode.CTR, iv=IV)
        plaintext = dec_session.update(ciphertext) + dec_session.finalize()

        assert plaintext[1:] == tail
        assert plaintext[0] in possible_first_bytes

    def test_concurrent_one_shot_round_trips_across_threads_are_correct(self) -> None:
        # Multiple independent one-shot encrypt/decrypt round trips,
        # genuinely running with the GIL released and overlapping in
        # wall-clock time, must each produce the correct plaintext -- no
        # cross-thread interference from the shared engine dispatch code.
        n_threads = 8
        results: list[bool] = [False] * n_threads
        errors: list[BaseException] = []
        lock = threading.Lock()

        def work(i: int) -> None:
            try:
                key = TwofishKey(bytes([i] * 16))
                data = bytes([(i * 37 + j) % 256 for j in range(20_000 + i * 500)])
                iv, ciphertext = key.encrypt(data)
                plaintext = key.decrypt(ciphertext, iv=iv)
                results[i] = plaintext == data
            except BaseException as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, errors
        assert all(results)
