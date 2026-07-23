#!/usr/bin/env python3
"""Throughput benchmark: new session-based API vs. the pre-RFC-0001 API.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), slice 17 ("Cleanup: split
lib.rs, benchmark vs 20% threshold"). Testing Strategy: "benchmark
new-engine whole-message throughput vs. current on a 1-10 MB payload...
threshold: within 20% of current throughput".

RFC 0003 (docs/rfcs/0003-interop-breadth.md), Testing Strategy ("Benchmark
rows") and slice 6: adds `TwofishXTS` and `ctr_width` rows, new-API only
(neither construct exists on the old API baseline). These rows carry **no
threshold gate** -- they are datapoints for the upstream RustCrypto perf
conversation (see the RFC's Non-goals, "Upstream performance work"), not a
pass/fail check.

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
from typing import Literal

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

# RFC 0003: CTR widths benchmarked alongside PAYLOADS above. 128 is today's
# default (the pre-RFC-0003 behavior); 64/32 are the new narrower widths.
CTR_WIDTHS: tuple[Literal[32, 64, 128], ...] = (128, 64, 32)

# RFC 0003: TwofishXTS rows. `xts_key` below is a fresh random 64-byte
# concatenated key (key1 || key2, the max 32-byte-per-half size) -- distinct
# halves with overwhelming probability, satisfying the equal-halves guard.
#
# "512-byte data-unit loop": VeraCrypt's own fixed data-unit size, encrypted
# as many independent one-shot calls (one per sector, each its own tweak) --
# the realistic disk-encryption access pattern, not one big call. Sized to
# ~100 KB total per rep for a direct comparison against the "100 KB"
# PAYLOADS cell above.
XTS_SECTOR_SIZE = 512
XTS_SECTOR_COUNT = 200  # 200 * 512 B ~= 100 KB per rep
XTS_SECTOR_REPS = 50

# A single large data unit -- XTS's 2**20-block (16 MiB) ceiling comfortably
# covers 10 MB in one call, for a direct comparison against the "10 MB"
# PAYLOADS cell above.
XTS_LARGE_UNIT_SIZE = 10 * 1024 * 1024
XTS_LARGE_UNIT_REPS = 8


def mb_per_s(nbytes: int, reps: int, elapsed: float) -> float:
    total_bytes = nbytes * reps
    return (total_bytes / (1024 * 1024)) / elapsed


def timed(fn: Callable[[], None], reps: int) -> float:
    start = time.perf_counter()
    for _ in range(reps):
        fn()
    return time.perf_counter() - start


def bench_new_api() -> list[tuple[str, str, float]]:
    from oxifish import Mode, Padding, TwofishKey, TwofishXTS

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

    # RFC 0003: ctr_width rows. One-shot only (CTR has no alignment/padding
    # concern to also exercise via streaming, unlike the CBC rows above);
    # width=128 is today's default CTR behavior, benchmarked here for the
    # first time alongside the new 64/32 widths it sits next to.
    for width in CTR_WIDTHS:
        for label, size, reps in PAYLOADS:
            data = secrets.token_bytes(size)
            ct = key.encrypt(data, Mode.CTR, iv=IV, ctr_width=width)

            def ctr_encrypt(data: bytes = data, width: Literal[32, 64, 128] = width) -> None:
                key.encrypt(data, Mode.CTR, iv=IV, ctr_width=width)

            def ctr_decrypt(ct: bytes = ct, width: Literal[32, 64, 128] = width) -> None:
                key.decrypt(ct, Mode.CTR, iv=IV, ctr_width=width)

            # A benchmark that measures the wrong output is worthless --
            # verify the round trip once before timing it.
            assert key.decrypt(ct, Mode.CTR, iv=IV, ctr_width=width) == data

            t = timed(ctr_encrypt, reps)
            rows.append((f"ctr encrypt w={width}", label, mb_per_s(size, reps, t)))

            t = timed(ctr_decrypt, reps)
            rows.append((f"ctr decrypt w={width}", label, mb_per_s(len(ct), reps, t)))

    # RFC 0003: TwofishXTS rows (new-API only -- XTS does not exist on the
    # old API baseline). Random 64-byte key -- distinct halves w.h.p.
    xts_key = secrets.token_bytes(64)
    xts = TwofishXTS(xts_key)

    sectors = [secrets.token_bytes(XTS_SECTOR_SIZE) for _ in range(XTS_SECTOR_COUNT)]
    sector_ct = [xts.encrypt(s, tweak=i) for i, s in enumerate(sectors)]
    assert [xts.decrypt(c, tweak=i) for i, c in enumerate(sector_ct)] == sectors

    def xts_encrypt_sectors() -> None:
        for i, s in enumerate(sectors):
            xts.encrypt(s, tweak=i)

    def xts_decrypt_sectors() -> None:
        for i, ct in enumerate(sector_ct):
            xts.decrypt(ct, tweak=i)

    total_sector_bytes = XTS_SECTOR_SIZE * XTS_SECTOR_COUNT

    t = timed(xts_encrypt_sectors, XTS_SECTOR_REPS)
    rows.append(("xts enc 512B", "100 KB", mb_per_s(total_sector_bytes, XTS_SECTOR_REPS, t)))

    t = timed(xts_decrypt_sectors, XTS_SECTOR_REPS)
    rows.append(("xts dec 512B", "100 KB", mb_per_s(total_sector_bytes, XTS_SECTOR_REPS, t)))

    large_unit = secrets.token_bytes(XTS_LARGE_UNIT_SIZE)
    large_unit_ct = xts.encrypt(large_unit, tweak=0)
    assert xts.decrypt(large_unit_ct, tweak=0) == large_unit

    def xts_encrypt_large() -> None:
        xts.encrypt(large_unit, tweak=0)

    def xts_decrypt_large() -> None:
        xts.decrypt(large_unit_ct, tweak=0)

    t = timed(xts_encrypt_large, XTS_LARGE_UNIT_REPS)
    rows.append(("xts encrypt", "10 MB", mb_per_s(len(large_unit), XTS_LARGE_UNIT_REPS, t)))

    t = timed(xts_decrypt_large, XTS_LARGE_UNIT_REPS)
    rows.append(("xts decrypt", "10 MB", mb_per_s(len(large_unit_ct), XTS_LARGE_UNIT_REPS, t)))

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
