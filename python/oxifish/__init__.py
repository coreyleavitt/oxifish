"""Python bindings for the RustCrypto Twofish block cipher implementation.

This package provides a session-oriented Twofish API: construct a
`TwofishKey` once, then either call its one-shot `encrypt`/`decrypt` (the
dominant use case) or open a streaming `TwofishSession` for incremental
processing. CBC, CTR, CFB, and OFB are reachable via the shared `Mode`
parameter; ECB (which leaks block-level plaintext patterns) is reachable
only via the dedicated `ecb_encryptor`/`ecb_decryptor` factories. See RFC
0001 (`docs/rfcs/0001-twofish-session-api.md`) for the full design
rationale.

Example (one-shot, the KeePass hot path -- IV lives in the KDBX header):
    >>> key = TwofishKey(derived_key)
    >>> plaintext = key.decrypt(ciphertext, iv=header_iv)  # PKCS7 default

Example (one-shot, auto-generated IV):
    >>> iv, ciphertext = key.encrypt(plaintext)
    >>> ct = key.encrypt(aligned, iv=iv, padding=Padding.NONE)

Example (streaming):
    >>> enc = key.encryptor(Mode.CFB, iv=iv)
    >>> out = enc.update(chunk_a) + enc.update(chunk_b) + enc.finalize()

Example (ECB, KAT/interop path -- single block only):
    >>> block_ct = key.ecb_encryptor(padding=Padding.NONE).finalize(block)

Security Note:
    The Twofish algorithm uses key-dependent S-boxes, which means this
    implementation is NOT constant-time and may be vulnerable to cache
    timing attacks. This is an inherent property of Twofish, not a flaw
    in this implementation. For new applications, consider using AES
    (with hardware acceleration) or ChaCha20 instead. See SECURITY.md for
    the full security scope, including this package's key/IV zeroization
    story.
"""

from enum import StrEnum
from importlib.metadata import version as _get_version
from typing import NamedTuple, Self, TypeAlias, overload

__version__ = _get_version("oxifish")

from oxifish._oxifish import (
    # Constants
    BLOCK_SIZE,
    # New surface (RFC 0001 slice 15): defined in Rust via
    # `pyo3::create_exception!`, not as a plain Python class here -- see
    # the reconciliation note by its re-export below.
    DecryptionError,
    TwofishSession,
)
from oxifish._oxifish import TwofishKey as _TwofishKey

# ============================================================================
# New surface (RFC 0001): key + module boundary
# ============================================================================
#
# `oxifish._oxifish.TwofishKey` is a `#[pyclass(subclass)]` written in Rust
# (src/lib.rs) that owns construction (key-length validation) and the
# expanded key schedule. `TwofishKey` below is the public, Python-facing
# subclass: per the RFC's module boundary, the Rust layer owns construction
# and the key schedule, while this Python layer owns `Buffer` coercion and
# (in later slices) `Mode`/`Padding` string coercion and `EncryptResult`
# wrapping. Later slices add the one-shot `encrypt`/`decrypt`, streaming
# `encryptor`/`decryptor`, and ECB factory methods this class does not yet
# expose.

Buffer: TypeAlias = bytes | bytearray | memoryview
"""Accepted input type for key/data arguments throughout the new surface.

`collections.abc.Buffer` (the structural buffer-protocol ABC) is 3.12+;
this package's floor is 3.11, hence the explicit union.
"""


def _coerce_buffer(value: object, name: str) -> bytes:
    """Coerce a `Buffer`-protocol value to `bytes`.

    Used at every facade coercion site (key/data/iv). Plain `bytes()`
    mis-accepts two poisonous inputs: `str` (raises the raw, confusing
    "string argument without an encoding" `TypeError`) and `int` (silently
    *succeeds* -- `bytes(5) == b"\\x00" * 5` -- which would let e.g.
    `key.encrypt(5)` silently encrypt five zero bytes). Both are rejected
    here with a message naming the parameter and the type received, before
    they can reach `bytes()`. Every other buffer-protocol object
    (bytearray, memoryview, array.array, ...) is passed through to
    `bytes()` unchanged -- this deliberately does not narrow to an
    isinstance whitelist.
    """
    if isinstance(value, (str, int)):
        raise TypeError(_buffer_type_error_message(value, name))
    try:
        return bytes(value)  # type: ignore[call-overload,no-any-return]
    except TypeError as exc:
        raise TypeError(_buffer_type_error_message(value, name)) from exc


def _buffer_type_error_message(value: object, name: str) -> str:
    hint = " -- use .encode() to convert text to bytes" if isinstance(value, str) else ""
    return (
        f"{name} must be a bytes-like object (bytes, bytearray, memoryview), "
        f"got {type(value).__name__}{hint}"
    )


class Mode(StrEnum):
    """Streaming/one-shot cipher mode selector.

    Deliberately excludes ECB: RFC 0001 keeps ECB reachable only via
    `TwofishKey.ecb_encryptor`/`ecb_decryptor`, never via the shared
    `Mode`-taking methods -- ECB's lack of semantic security should never
    be one string swap away from CBC/CTR/CFB/OFB. The string `"ecb"` is
    rejected by the shared factories exactly like any other unknown mode.
    """

    CBC = "cbc"
    CTR = "ctr"
    CFB = "cfb"
    OFB = "ofb"


class Padding(StrEnum):
    """Padding schemes for the new surface's block-mode sessions."""

    PKCS7 = "pkcs7"
    NONE = "none"
    ISO7816 = "iso7816"
    ANSIX923 = "ansix923"
    ZEROS = "zeros"


class EncryptResult(NamedTuple):
    """Return value of auto-IV `TwofishKey.encrypt()`: the IV and ciphertext
    that must travel together."""

    iv: bytes
    ciphertext: bytes


# `DecryptionError` itself is re-exported directly from `oxifish._oxifish`
# (imported above) rather than defined here as a Python class -- slice 7
# originally pinned an *inert* `class DecryptionError(ValueError): ...` in
# this module; slice 15 ("Misuse machine + DecryptionError") reconciles
# that with the RFC's actual wiring requirement. The reason is structural:
# `TwofishKey.decrypt` has a Python facade that could translate a
# distinguishable Rust error into a Python-defined type, but
# `TwofishSession` (returned directly from Rust, per the RFC's module
# boundary) has no such facade -- `TwofishSession.finalize()` must be able
# to raise the exact same exception type with no Python-side call site to
# do the translation. Defining `DecryptionError` once in Rust (via
# `pyo3::create_exception!`, subclassing `PyValueError`) and raising it
# directly from both entry points is the only mechanism that covers both
# surfaces uniformly. From here, `oxifish.DecryptionError` is unchanged
# from the RFC's Proposed Interface pseudocode: an importable, catchable
# `ValueError` subclass named `DecryptionError` -- which language defines
# it is an implementation detail this module hides.


class TwofishKey(_TwofishKey):
    """A Twofish key: constructed once, reused across one-shot calls and
    streaming sessions.

    Args:
        key: 16, 24, or 32 bytes (128/192/256-bit key).

    Raises:
        ValueError: If key length is invalid.
    """

    def __new__(cls, key: Buffer) -> Self:
        # Coerce the accepted Buffer union (bytes/bytearray/memoryview) to
        # `bytes` before it reaches the Rust constructor, which extracts a
        # borrowed `&[u8]` view (bytes-only). Construction is small,
        # GIL-held, one-shot work -- unlike the streaming/one-shot transform
        # paths (RFC 0001 slice 12+), there is no GIL-release copy-timing
        # concern here to work around.
        return super().__new__(cls, _coerce_buffer(key, "key"))

    @overload
    def encrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: None = None,
        padding: Padding | str | None = None,
    ) -> EncryptResult: ...
    @overload
    def encrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer,
        padding: Padding | str | None = None,
    ) -> bytes: ...
    def encrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer | None = None,
        padding: Padding | str | None = None,
    ) -> bytes | EncryptResult:
        """Encrypt `data` (one-shot).

        Routed through `_encrypt_raw`, which drives the same engine
        `ingest`/`close_out` path streaming sessions use (RFC 0001
        Contracts: engine unification) -- chunking invariance is a
        structural guarantee, not a coincidence of two independently
        correct implementations. `mode` dispatch (RFC 0001 slice 10,
        "Remaining modes") happens entirely on the Rust side, in the one
        place mode strings are parsed (`parse_mode`); this method only
        coerces `Mode | str` to its string value.

        Args:
            data: Plaintext, any length (`Buffer`: bytes/bytearray/
                memoryview). For CBC, `padding` fills to block alignment.
            mode: `Mode` member or its exact string value. Defaults to
                CBC. The string `"ecb"` and any other unrecognized value
                raise `ValueError` (see Raises) -- ECB is reachable only
                via `ecb_encryptor`/`ecb_decryptor`.
            iv: 16-byte initialization vector -- for CTR this is the full
                initial counter block (`Ctr128BE`), not a nonce+counter
                split. Omitted (`None`, the default): a fresh IV is
                generated via the OS CSPRNG (`getrandom`, RFC 0001 slice
                13 "Auto-IV") and returned alongside the ciphertext as
                `EncryptResult(iv, ciphertext)` -- the two values that
                must travel together. Supplied explicitly: the caller
                already owns it, so this returns bare `ciphertext` bytes
                (symmetric with `decrypt`).
            padding: For CBC, `None` defaults to PKCS7 (the RFC's stated
                CBC default); any `Padding` member or its exact string
                value is otherwise accepted. For CTR/CFB/OFB (stream
                modes), `padding` must stay `None` -- passing *any*
                explicit value, including `Padding.NONE`/`"none"`, raises
                `ValueError` (RFC Contracts: "Padding defaults &
                rejection").

        Returns:
            `EncryptResult(iv, ciphertext)` when `iv` was omitted; bare
            `ciphertext` bytes when `iv` was supplied.

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; (`padding="none"`) a `data` length that
                is not a multiple of the block size; or an explicit
                `padding` on a stream mode.
        """
        padding_str = None if padding is None else str(padding)
        iv_bytes = None if iv is None else _coerce_buffer(iv, "iv")
        used_iv, ciphertext = self._encrypt_raw(
            _coerce_buffer(data, "data"), str(mode), iv_bytes, padding_str
        )
        if iv is None:
            return EncryptResult(bytes(used_iv), bytes(ciphertext))
        return bytes(ciphertext)

    def decrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer,
        padding: Padding | str | None = None,
    ) -> bytes:
        """Decrypt `data` (one-shot). See `encrypt` re: engine routing and
        `mode` dispatch.

        Args:
            data: Ciphertext, any length (`Buffer`).
            mode: `Mode` member or its exact string value. Defaults to
                CBC. See `encrypt` re: `"ecb"`/unrecognized-mode rejection.
            iv: 16-byte initialization vector (always required -- unlike
                `encrypt`, `decrypt` has no auto-IV overload: decrypting
                requires the IV the corresponding encryption used, which
                by definition cannot be generated here).
            padding: `None` defaults to PKCS7 for CBC, matching `encrypt`.
                Must stay `None` for CTR/CFB/OFB -- see `encrypt`.

        Returns:
            Plaintext bytes.

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; (`padding="none"`) a `data` length that
                is not a multiple of the block size; or an explicit
                `padding` on a stream mode.
            DecryptionError: invalid/corrupted padded ciphertext (a
                `ValueError` subclass; see `DecryptionError`'s docstring
                for the exact scope).
        """
        padding_str = None if padding is None else str(padding)
        return self._decrypt_raw(
            _coerce_buffer(data, "data"), str(mode), _coerce_buffer(iv, "iv"), padding_str
        )

    def encryptor(
        self,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer | None = None,
        padding: Padding | str | None = None,
    ) -> TwofishSession:
        """Create a streaming encryptor session.

        Routed through `_encryptor_raw`, sharing `mode`/`padding` dispatch
        (`parse_mode`, the single mode-validation site) with `encrypt`. The
        returned `TwofishSession.update`/`.finalize` accept `Buffer`
        (bytes/bytearray/memoryview) directly, copying the input into
        engine-owned memory while the GIL is held (RFC Concurrency
        contract) at the Rust boundary -- there is no Python-side wrapper
        around `TwofishSession` to do that coercion, unlike `TwofishKey`.

        Args:
            mode: `Mode` member or its exact string value. Defaults to
                CBC. The string `"ecb"` and any other unrecognized value
                raise `ValueError` -- ECB is reachable only via
                `ecb_encryptor`.
            iv: 16-byte initialization vector -- for CTR this is the full
                initial counter block. Omitted (`None`, the default): a
                fresh IV is generated via the OS CSPRNG (RFC 0001 slice 13
                "Auto-IV") and readable on the returned session's `.iv`
                (before and after `finalize()`) so callers can store it --
                the "`.iv` contract". Supplied explicitly: used as-is.
            padding: For CBC, `None` defaults to PKCS7; any `Padding`
                member or its exact string value is otherwise accepted.
                For CTR/CFB/OFB, `padding` must stay `None` -- any explicit
                value, including `Padding.NONE`/`"none"`, raises
                `ValueError`.

        Returns:
            A fresh `TwofishSession` (`direction == "encrypt"`, `.iv`
            readable).

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; or an explicit `padding` on a stream
                mode.
        """
        padding_str = None if padding is None else str(padding)
        iv_bytes = None if iv is None else _coerce_buffer(iv, "iv")
        return self._encryptor_raw(str(mode), iv_bytes, padding_str)

    def decryptor(
        self,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer,
        padding: Padding | str | None = None,
    ) -> TwofishSession:
        """Create a streaming decryptor session. See `encryptor` re: engine
        routing and `mode`/`padding` dispatch.

        Args:
            mode: `Mode` member or its exact string value. Defaults to
                CBC. See `encryptor` re: `"ecb"`/unrecognized-mode
                rejection.
            iv: 16-byte initialization vector (always required for
                decryption -- `decryptor` has no auto-IV overload, see
                `decrypt`).
            padding: `None` defaults to PKCS7 for CBC, matching
                `encryptor`. Must stay `None` for CTR/CFB/OFB.

        Returns:
            A fresh `TwofishSession` (`direction == "decrypt"`, `.iv`
            readable).

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; or an explicit `padding` on a stream
                mode. Padded-decrypt failures surface as `DecryptionError`
                at `finalize()`, not here.
        """
        padding_str = None if padding is None else str(padding)
        return self._decryptor_raw(str(mode), _coerce_buffer(iv, "iv"), padding_str)

    def ecb_encryptor(self, *, padding: Padding | str) -> TwofishSession:
        """Create an ECB encryptor session (RFC 0001 slice 11, "ECB
        factories + KATs").

        ECB is deliberately unreachable via `encrypt`/`encryptor`'s `Mode`
        parameter -- it leaks block-level plaintext patterns and should
        only be used for single-block operations or explicit interop; this
        factory is the sole way to reach it. Unlike `encrypt`/`encryptor`,
        `padding` is mandatory here (RFC Contracts: "ECB factories require
        explicit padding=") -- there is no PKCS7-by-default carve-out.

        The returned session has no `iv` (`.iv` raises `AttributeError`);
        for the raw-block KAT/interop idiom, `Padding.NONE` plus a single
        call to `finalize(block)` is a complete one-liner:
        `key.ecb_encryptor(padding=Padding.NONE).finalize(block)`.

        Args:
            padding: Any `Padding` member or its exact string value
                (including `Padding.NONE`/`"none"` for raw, unpadded
                blocks).

        Returns:
            A fresh `TwofishSession` (`mode == "ecb"`,
            `direction == "encrypt"`), borrowing this key's shared
            schedule.

        Raises:
            ValueError: Unrecognized `padding` string.
        """
        return self._ecb_encryptor_raw(str(padding))

    def ecb_decryptor(self, *, padding: Padding | str) -> TwofishSession:
        """Create an ECB decryptor session. See `ecb_encryptor` re:
        mandatory `padding`, the missing `iv`, and the one-liner idiom.

        Args:
            padding: Any `Padding` member or its exact string value.

        Returns:
            A fresh `TwofishSession` (`mode == "ecb"`,
            `direction == "decrypt"`), borrowing this key's shared
            schedule.

        Raises:
            ValueError: Unrecognized `padding` string.
            DecryptionError: (at `finalize()`) invalid/corrupted padded
                ciphertext -- a `ValueError` subclass.
        """
        return self._ecb_decryptor_raw(str(padding))


__all__ = [
    # Constants
    "BLOCK_SIZE",
    "Buffer",
    "Mode",
    "Padding",
    "EncryptResult",
    "DecryptionError",
    "TwofishKey",
    "TwofishSession",
]
