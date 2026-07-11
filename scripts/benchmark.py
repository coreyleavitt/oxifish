#!/usr/bin/env python3
"""Throughput benchmark: new session-based API vs. the pre-RFC-0001 API.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), slice 17 ("Cleanup: split
lib.rs, benchmark vs 20% threshold"). Testing Strategy: "benchmark
new-engine whole-message throughput vs. current on a 1-10 MB payload...
threshold: within 20% of current throughput".

This script is deliberately API-agnostic at the call site: it detects
whether the `oxifish` importable in the running interpreter is the new
surface (`TwofishKey`/`Mode`) or the old one (`TwofishCBC`) and benchmarks
whichever it finds, emitting the same row shape either way so two runs (one
per interpreter/venv) can be diffed directly.

Usage:
    uv run --no-sync python scripts/benchmark.py            # new API (this repo's venv)
    /path/to/baseline-venv/bin/python scripts/benchmark.py  # old API (baseline worktree's venv)

Payload sizes and repetition counts are chosen so each cell takes on the
order of tens of milliseconds to a couple of seconds; MB/s is computed from
wall-clock time around the pure encrypt/decrypt call (object construction
happens once outside the timed loop, matching how a real caller amortizes
key-schedule setup across many calls).
"""

from __future__ import annotations

import os
import secrets
import sys
import time
from collections.abc import Callable

KEY = secrets.token_bytes(32)
IV = secrets.token_bytes(16)

# (label, size in bytes, repetitions). Repetitions scaled so total time per
# cell stays in a reasonable range even for the 10 MB payload.
PAYLOADS = [
    ("1 KB", 1 * 1024, 2000),
    ("100 KB", 100 * 1024, 200),
    ("10 MB", 10 * 1024 * 1024, 8),
]

STREAM_CHUNK = 64 * 1024  # aligned chunk size for streaming benchmarks


def mb_per_s(nbytes: int, reps: int, elapsed: float) -> float:
    total_bytes = nbytes * reps
    return (total_bytes / (1024 * 1024)) / elapsed


def timed(fn: Callable[[], None], reps: int) -> float:
    start = time.perf_counter()
    for _ in range(reps):
        fn()
    return time.perf_counter() - start


def bench_new_api() -> list[tuple[str, str, float]]:
    from oxifish import Mode, Padding, TwofishKey

    key = TwofishKey(KEY)
    rows: list[tuple[str, str, float]] = []

    for label, size, reps in PAYLOADS:
        data = secrets.token_bytes(size)
        aligned = data[: size - (size % 16)] or data[:16]
        ct_aligned = key.encrypt(aligned, Mode.CBC, iv=IV, padding=Padding.NONE)

        def one_shot_encrypt(aligned: bytes = aligned) -> None:
            key.encrypt(aligned, Mode.CBC, iv=IV, padding=Padding.NONE)

        def one_shot_decrypt(ct_aligned: bytes = ct_aligned) -> None:
            key.decrypt(ct_aligned, Mode.CBC, iv=IV, padding=Padding.NONE)

        t = timed(one_shot_encrypt, reps)
        rows.append(("one-shot encrypt", label, mb_per_s(len(aligned), reps, t)))

        t = timed(one_shot_decrypt, reps)
        rows.append(("one-shot decrypt", label, mb_per_s(len(ct_aligned), reps, t)))

        def stream_encrypt(aligned: bytes = aligned) -> None:
            enc = key.encryptor(Mode.CBC, iv=IV, padding=Padding.NONE)
            out = bytearray()
            for i in range(0, len(aligned), STREAM_CHUNK):
                out += enc.update(aligned[i : i + STREAM_CHUNK])
            out += enc.finalize()

        t = timed(stream_encrypt, reps)
        rows.append(("streaming encrypt", label, mb_per_s(len(aligned), reps, t)))

        def stream_decrypt(ct_aligned: bytes = ct_aligned) -> None:
            dec = key.decryptor(Mode.CBC, iv=IV, padding=Padding.NONE)
            out = bytearray()
            for i in range(0, len(ct_aligned), STREAM_CHUNK):
                out += dec.update(ct_aligned[i : i + STREAM_CHUNK])
            out += dec.finalize()

        # A benchmark that measures the wrong output is worthless -- verify
        # the round trip once before timing it.
        verify = key.decryptor(Mode.CBC, iv=IV, padding=Padding.NONE)
        verify_out = bytearray()
        for i in range(0, len(ct_aligned), STREAM_CHUNK):
            verify_out += verify.update(ct_aligned[i : i + STREAM_CHUNK])
        verify_out += verify.finalize()
        assert bytes(verify_out) == aligned

        t = timed(stream_decrypt, reps)
        rows.append(("streaming decrypt", label, mb_per_s(len(ct_aligned), reps, t)))

        # Padded streaming decrypt is the one path with different buffering:
        # the session withholds the final block until finalize() (holdback).
        # New-API only -- the old API has no padded streaming decrypt to
        # mirror, so this row has no baseline counterpart.
        ct_padded = key.encrypt(aligned, Mode.CBC, iv=IV, padding=Padding.PKCS7)

        def stream_decrypt_pkcs7(ct_padded: bytes = ct_padded) -> None:
            dec = key.decryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
            out = bytearray()
            for i in range(0, len(ct_padded), STREAM_CHUNK):
                out += dec.update(ct_padded[i : i + STREAM_CHUNK])
            out += dec.finalize()

        verify = key.decryptor(Mode.CBC, iv=IV, padding=Padding.PKCS7)
        verify_out = bytearray()
        for i in range(0, len(ct_padded), STREAM_CHUNK):
            verify_out += verify.update(ct_padded[i : i + STREAM_CHUNK])
        verify_out += verify.finalize()
        assert bytes(verify_out) == aligned

        t = timed(stream_decrypt_pkcs7, reps)
        rows.append(("stream dec pkcs7", label, mb_per_s(len(ct_padded), reps, t)))

    return rows


def bench_old_api() -> list[tuple[str, str, float]]:
    from oxifish import TwofishCBC  # type: ignore[attr-defined]

    cipher = TwofishCBC(KEY)
    rows: list[tuple[str, str, float]] = []

    for label, size, reps in PAYLOADS:
        data = secrets.token_bytes(size)
        aligned = data[: size - (size % 16)] or data[:16]
        ct_aligned = cipher.encrypt(aligned, IV)

        def one_shot_encrypt(aligned: bytes = aligned) -> None:
            cipher.encrypt(aligned, IV)

        def one_shot_decrypt(ct_aligned: bytes = ct_aligned) -> None:
            cipher.decrypt(ct_aligned, IV)

        t = timed(one_shot_encrypt, reps)
        rows.append(("one-shot encrypt", label, mb_per_s(len(aligned), reps, t)))

        t = timed(one_shot_decrypt, reps)
        rows.append(("one-shot decrypt", label, mb_per_s(len(ct_aligned), reps, t)))

        def stream_encrypt(aligned: bytes = aligned) -> None:
            enc = cipher.encryptor(IV)
            out = bytearray()
            for i in range(0, len(aligned), STREAM_CHUNK):
                out += enc.update(aligned[i : i + STREAM_CHUNK])

        t = timed(stream_encrypt, reps)
        rows.append(("streaming encrypt", label, mb_per_s(len(aligned), reps, t)))

        def stream_decrypt(ct_aligned: bytes = ct_aligned) -> None:
            dec = cipher.decryptor(IV)
            out = bytearray()
            for i in range(0, len(ct_aligned), STREAM_CHUNK):
                out += dec.update(ct_aligned[i : i + STREAM_CHUNK])

        # A benchmark that measures the wrong output is worthless -- verify
        # the round trip once before timing it. (Old API's CBC decryptor has
        # no finalize() -- update() alone returns the full block-aligned
        # plaintext, no padding/holdback concept.)
        verify = cipher.decryptor(IV)
        verify_out = bytearray()
        for i in range(0, len(ct_aligned), STREAM_CHUNK):
            verify_out += verify.update(ct_aligned[i : i + STREAM_CHUNK])
        assert bytes(verify_out) == aligned

        t = timed(stream_decrypt, reps)
        rows.append(("streaming decrypt", label, mb_per_s(len(ct_aligned), reps, t)))

    return rows


def main() -> None:
    import oxifish

    if hasattr(oxifish, "TwofishKey"):
        api = "new"
        rows = bench_new_api()
    elif hasattr(oxifish, "TwofishCBC"):
        api = "old"
        rows = bench_old_api()
    else:
        print("ERROR: neither TwofishKey nor TwofishCBC found in oxifish", file=sys.stderr)
        sys.exit(1)

    print(
        f"# oxifish benchmark -- api={api} version={getattr(oxifish, '__version__', '?')} "
        f"python={sys.version.split()[0]} pid={os.getpid()}"
    )
    print(f"{'path':<20}{'size':<10}{'MB/s':>12}")
    for path, size, rate in rows:
        print(f"{path:<20}{size:<10}{rate:>12.2f}")


if __name__ == "__main__":
    main()
