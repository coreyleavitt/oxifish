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
    >>> derived_key = bytes(range(32))  # stand-in for a KeePass-derived key
    >>> key = TwofishKey(derived_key)
    >>> # In real usage, `ciphertext`/`header_iv` come from the KDBX file --
    >>> # synthesized here via a real encrypt() call so this example runs.
    >>> header_iv, ciphertext = key.encrypt(b"a secret message")
    >>> plaintext = key.decrypt(ciphertext, iv=header_iv)  # PKCS7 default

Example (one-shot, auto-generated IV):
    >>> iv, ciphertext = key.encrypt(plaintext)
    >>> aligned = bytes(range(16))  # Padding.NONE requires block-aligned data
    >>> import secrets
    >>> iv2 = secrets.token_bytes(16)  # a fresh IV -- never reuse `iv` from above
    >>> ct = key.encrypt(aligned, iv=iv2, padding=Padding.NONE)

Example (streaming):
    >>> chunk_a, chunk_b = b"first chunk of ", b"the message"
    >>> enc = key.encryptor(Mode.CFB)  # iv omitted -> fresh IV auto-generated
    >>> out = enc.update(chunk_a) + enc.update(chunk_b) + enc.finalize()

Example (ctr_width, homegrown split nonce||counter formats -- the
PyCryptodome-style `Counter(nonce=..., initial_value=...)` layouts people
built the dead `twofish` package's own CTR support out of):
    >>> nonce8 = bytes(range(8))
    >>> counter = 0
    >>> iv3 = nonce8 + counter.to_bytes(8, "big")  # 16-byte initial counter block
    >>> ct64 = key.encrypt(aligned, Mode.CTR, iv=iv3, ctr_width=64)
    >>> key.decrypt(ct64, Mode.CTR, iv=iv3, ctr_width=64) == aligned
    True

Example (ECB, KAT/interop path -- single block only):
    >>> block = bytes(range(16))  # exactly one block
    >>> block_ct = key.ecb_encryptor(padding=Padding.NONE).finalize(block)

Example (XTS, disk-volume interop -- VeraCrypt/TrueCrypt>=5.0/dm-crypt
`twofish-xts-plain64`; a structurally separate construct from everything
above, see `TwofishXTS`):
    >>> from oxifish import TwofishXTS
    >>> xts_key = bytes(range(32)) + bytes(range(32, 64))  # key1 || key2, must differ
    >>> xts = TwofishXTS(xts_key)
    >>> sector = bytes(512)  # VeraCrypt's data unit is always 512 bytes
    >>> data_unit = 42  # e.g. byte_offset // 512 -- a position, not a nonce
    >>> sector_ct = xts.encrypt(sector, tweak=data_unit)
    >>> xts.decrypt(sector_ct, tweak=data_unit) == sector
    True

Security Note:
    The Twofish algorithm uses key-dependent S-boxes, which means this
    implementation is NOT constant-time and may be vulnerable to cache
    timing attacks. This is an inherent property of Twofish, not a flaw
    in this implementation. For new applications, consider using AES
    (with hardware acceleration) or ChaCha20 instead. See SECURITY.md for
    the full security scope, including this package's key/IV zeroization
    story.
"""

# enum/typing are imported as modules for StrEnum and NamedTuple: this
# fully-annotated module doubles as its own stub, and binding those names
# here (even underscore-aliased) fails stubtest wherever typeshed's
# declaration and the runtime object disagree (NamedTuple is a class in
# typeshed but a function at runtime; StrEnum._generate_next_value_ is a
# staticmethod in typeshed but not on 3.11). stubtest skips foreign module
# objects, so module-qualified access sidesteps the whole class of mismatch.
import enum
import typing
from importlib.metadata import version as _get_version
from typing import Literal, Self, TypeAlias, overload

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
from oxifish._oxifish import TwofishXTS as _TwofishXTS

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


_CTR_WIDTHS = (32, 64, 128)


def _validate_ctr_width(ctr_width: int) -> int:
    """Validate `ctr_width` against the catalog `{32, 64, 128}` (RFC 0003
    §3).

    Runs in this Python facade -- not the Rust boundary -- for the same
    reason `_validate_tweak` does (see `TwofishXTS`, below): an
    out-of-catalog value (including one far outside any sane integer
    range, since the public parameter is a plain `int` at runtime despite
    its `Literal[32, 64, 128]` static type) raises the cataloged
    `ValueError` here, before it can reach a PyO3 integer parameter and
    raise the generic `OverflowError` instead.

    A type check runs ahead of the catalog membership check, and raises
    `TypeError` (not `ValueError`) -- catalog membership is a *value*
    concern, so it never runs against a value of the wrong type in the
    first place. Without this: `ctr_width=32.0` (a `float`) passes
    `ctr_width not in (32, 64, 128)` (Python `in` compares by `==`) and
    falls through to raise PyO3's generic, uncataloged `TypeError` at the
    raw layer instead; `ctr_width="64"` (a `str`) fails the membership
    check and raises the cataloged `ValueError` with a message that
    misleadingly reads as an out-of-catalog *value* rejection. Note
    `isinstance(True, int)` is `True`, so `bool` is deliberately not
    special-cased here -- `ctr_width=True` falls through to the catalog
    `ValueError` below (`True` is not in `{32, 64, 128}`), which is
    correct: `bool` is a legitimate (if silly) `int` subtype.
    """
    if not isinstance(ctr_width, int):
        raise TypeError(f"ctr_width must be an int, got {type(ctr_width).__name__}")
    # Canonicalize via the unbound base-int slot: an int subclass's
    # overridden `__eq__`/comparisons could otherwise claim in-catalog
    # membership for a payload the Rust layer (which extracts the true
    # PyLong payload) sees differently -- validation and the Rust layer
    # must see the same value.
    ctr_width = int.__index__(ctr_width)
    if ctr_width not in _CTR_WIDTHS:
        raise ValueError(f"invalid ctr_width {ctr_width}: expected one of 32, 64, 128")
    return ctr_width


def _resolve_ctr_width(ctr_width: int) -> int | None:
    """Validate `ctr_width`, then collapse it onto the raw layer's `None`
    sentinel when it equals the CTR default (128).

    The public `ctr_width: Literal[32, 64, 128] = 128` parameter (RFC 0003
    §3, pinned exact signature) has a *concrete* default, unlike `padding`
    (default `None`, itself not a valid `Padding` value) -- so this facade
    cannot distinguish "the caller omitted ctr_width" from "the caller
    passed 128 explicitly." The two are behaviorally identical for every
    mode (128 is CTR's own default width, and a no-op for every other
    mode), so collapsing both onto `None` before calling the raw method is
    exact, not a lossy approximation -- see `TwofishKey._encrypt_raw`'s
    docstring for the Rust-side half of this contract.

    The 128-collapse compares `_validate_ctr_width`'s CANONICALIZED return
    value, never the caller's original object -- re-comparing the original
    would hand a lying int subclass's `__eq__` a second chance to bypass
    the canonicalization the validator just performed.
    """
    resolved = _validate_ctr_width(ctr_width)
    return None if resolved == 128 else resolved


class Mode(enum.StrEnum):
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


class Padding(enum.StrEnum):
    """Padding schemes for the new surface's block-mode sessions."""

    PKCS7 = "pkcs7"
    NONE = "none"
    ISO7816 = "iso7816"
    ANSIX923 = "ansix923"
    ZEROS = "zeros"


class EncryptResult(typing.NamedTuple):
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
        ctr_width: Literal[32, 64, 128] = 128,
    ) -> EncryptResult: ...
    @overload
    def encrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer,
        padding: Padding | str | None = None,
        ctr_width: Literal[32, 64, 128] = 128,
    ) -> bytes: ...
    def encrypt(
        self,
        data: Buffer,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer | None = None,
        padding: Padding | str | None = None,
        ctr_width: Literal[32, 64, 128] = 128,
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
            ctr_width: The number of low-order bits of `iv` that increment
                (big-endian), for `Mode.CTR` only -- the NIST-style
                nonce||counter split legacy `Counter`-convention formats
                use (RFC 0003 §3). Defaults to 128 (today's behavior: the
                full 16-byte `iv` is the counter). Passing a non-default
                value for any mode other than CTR raises `ValueError`; the
                low `ctr_width` bits wrap through zero after
                `2**ctr_width - 1` blocks, after which further encryption
                under the same session raises `ValueError` rather than
                reusing keystream.

        Returns:
            `EncryptResult(iv, ciphertext)` when `iv` was omitted; bare
            `ciphertext` bytes when `iv` was supplied.

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; (`padding="none"`) a `data` length that
                is not a multiple of the block size; an explicit `padding`
                on a stream mode; an invalid `ctr_width`; `ctr_width` on a
                non-CTR mode; or CTR keystream exhaustion.
            TypeError: `ctr_width` is not an `int` (`bool` counts as
                `int`).
        """
        padding_str = None if padding is None else str(padding)
        iv_bytes = None if iv is None else _coerce_buffer(iv, "iv")
        used_iv, ciphertext = self._encrypt_raw(
            _coerce_buffer(data, "data"),
            str(mode),
            iv_bytes,
            padding_str,
            _resolve_ctr_width(ctr_width),
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
        ctr_width: Literal[32, 64, 128] = 128,
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
            ctr_width: See `encrypt` -- must match the value used to
                encrypt `data`.

        Returns:
            Plaintext bytes.

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; (`padding="none"`) a `data` length that
                is not a multiple of the block size; an explicit `padding`
                on a stream mode; an invalid `ctr_width`; `ctr_width` on a
                non-CTR mode; or CTR keystream exhaustion.
            DecryptionError: invalid/corrupted padded ciphertext (a
                `ValueError` subclass; see `DecryptionError`'s docstring
                for the exact scope).
            TypeError: `ctr_width` is not an `int` (`bool` counts as
                `int`).
        """
        padding_str = None if padding is None else str(padding)
        return self._decrypt_raw(
            _coerce_buffer(data, "data"),
            str(mode),
            _coerce_buffer(iv, "iv"),
            padding_str,
            _resolve_ctr_width(ctr_width),
        )

    def encryptor(
        self,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer | None = None,
        padding: Padding | str | None = None,
        ctr_width: Literal[32, 64, 128] = 128,
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
            ctr_width: See `TwofishKey.encrypt`.

        Returns:
            A fresh `TwofishSession` (`direction == "encrypt"`, `.iv`
            readable).

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; an explicit `padding` on a stream mode;
                an invalid `ctr_width`; or `ctr_width` on a non-CTR mode.
            TypeError: `ctr_width` is not an `int` (`bool` counts as
                `int`).
        """
        padding_str = None if padding is None else str(padding)
        iv_bytes = None if iv is None else _coerce_buffer(iv, "iv")
        return self._encryptor_raw(str(mode), iv_bytes, padding_str, _resolve_ctr_width(ctr_width))

    def decryptor(
        self,
        mode: Mode | str = Mode.CBC,
        *,
        iv: Buffer,
        padding: Padding | str | None = None,
        ctr_width: Literal[32, 64, 128] = 128,
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
            ctr_width: See `TwofishKey.encrypt` -- must match the value
                used to encrypt.

        Returns:
            A fresh `TwofishSession` (`direction == "decrypt"`, `.iv`
            readable).

        Raises:
            ValueError: invalid IV length; unrecognized `mode` or
                `padding` string; an explicit `padding` on a stream mode;
                an invalid `ctr_width`; or `ctr_width` on a non-CTR mode.
                Padded-decrypt failures surface as `DecryptionError` at
                `finalize()`, not here.
            TypeError: `ctr_width` is not an `int` (`bool` counts as
                `int`).
        """
        padding_str = None if padding is None else str(padding)
        return self._decryptor_raw(
            str(mode), _coerce_buffer(iv, "iv"), padding_str, _resolve_ctr_width(ctr_width)
        )

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

        This is also the migration path off the dead PyPI `twofish`
        package (RFC 0003), whose entire API was single-block `encrypt`/
        `decrypt` -- see the README's "Migrating from the `twofish`
        package" section for the one-liner above plus the session-reuse
        loop for multi-block work.

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
        mandatory `padding`, the missing `iv`, the one-liner idiom, and
        the migration path off the dead `twofish` package.

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


# ============================================================================
# XTS surface (RFC 0003 slice 4): TwofishXTS
# ============================================================================
#
# `oxifish._oxifish.TwofishXTS` is a `#[pyclass(subclass)]` written in Rust
# (src/xts_py.rs) that owns the two expanded `Twofish` schedules and the
# in-repo `XtsCipher` transform (src/xts.rs, slice 3). `TwofishXTS` below is
# the public, Python-facing subclass: it owns `Buffer` coercion, splitting
# one concatenated key into its two halves, the equal-halves guard, and
# `tweak` range validation -- the same two-layer split `TwofishKey` uses
# (RFC §2, "Implementation pattern pinned").

_XTS_VALID_KEY_LENGTHS = (32, 48, 64)


def _split_xts_key(key: bytes) -> tuple[bytes, bytes]:
    """Validate and split one concatenated XTS key into `(key1, key2)`.

    `key1` (IEEE 1619's "Key1") drives the data-block cipher; `key2`
    ("Key2") drives the tweak. Splitting an even-length buffer in half
    (rather than taking two separate constructor arguments) eliminates the
    "unequal key lengths" error case by construction and matches every real
    XTS key format (VeraCrypt's concatenated master keydata, dm-crypt/LUKS,
    pyca's XTS) -- see RFC 0003 §2.
    """
    if len(key) not in _XTS_VALID_KEY_LENGTHS:
        raise ValueError(
            "XTS key must be 32, 48, or 64 bytes (two 128, 192, or 256 bit "
            f"halves), got {len(key)} bytes"
        )
    half = len(key) // 2
    key1, key2 = key[:half], key[half:]
    if key1 == key2:
        # Equal halves void XTS's CCA-security argument and never occur in
        # real formats -- a plain (non-constant-time) comparison of
        # caller-supplied construction-time key material, not a decryption
        # oracle, so constant-time treatment buys nothing here (RFC §2).
        raise ValueError("XTS key halves must not be equal")
    return key1, key2


def _validate_tweak(tweak: int) -> int:
    """Validate `tweak` against IEEE 1619's full 128-bit tweak space.

    Runs in this Python facade (not the Rust boundary) specifically so an
    out-of-range value raises the cataloged `ValueError` -- never PyO3's
    generic `OverflowError`, which is what a `u128` parameter would raise on
    its own for a value outside `0..2**128` (RFC §2, RFC Contracts) -- the
    same reason `_validate_ctr_width` does (see `TwofishKey`, above).

    A type check runs ahead of the range check, and raises `TypeError` (not
    `ValueError`) -- range membership is a *value* concern, so it never runs
    against a value of the wrong type in the first place. Without this:
    `tweak="0"` or `tweak=0.0` (a `str`/`float`) both fail the `isinstance`
    guard and previously fell straight into the range branch's `ValueError`,
    misleadingly rendering as an out-of-range *value* rejection ("tweak must
    be a non-negative integer less than 2**128, got 0") rather than a type
    error. Note `isinstance(True, int)` is `True`, so `bool` is deliberately
    not special-cased here -- `tweak=True` passes the type guard and then
    the range check as `1`, which is correct: `bool` is a legitimate (if
    silly) `int` subtype.
    """
    if not isinstance(tweak, int):
        raise TypeError(f"tweak must be an int, got {type(tweak).__name__}")
    # Canonicalize via the unbound base-int slot: an int subclass's
    # overridden `__eq__`/comparisons could otherwise claim in-range
    # bounds for a payload the Rust layer (which extracts the true PyLong
    # payload) sees differently -- validation and the Rust layer must see
    # the same value.
    tweak = int.__index__(tweak)
    if not (0 <= tweak < 2**128):
        raise ValueError(f"tweak must be a non-negative integer less than 2**128, got {tweak}")
    return tweak


class TwofishXTS(_TwofishXTS):
    """A Twofish-XTS cipher: IEEE 1619 tweakable, ciphertext-stealing mode
    for sector/data-unit-oriented encryption -- VeraCrypt, TrueCrypt >= 5.0,
    and dm-crypt/LUKS `twofish-xts-plain64` volumes all use it.

    Unlike `TwofishKey`, this class is **not** reachable through `Mode`:
    XTS takes a double-length key and a per-call tweak instead of an IV, has
    no padding parameter (ciphertext stealing handles non-block-multiple
    lengths instead), and is one-shot/random-access rather than streaming --
    see RFC 0003's First-Principles Ideal for why it gets its own construct.
    `repr()` reports `key_size` in *bytes* (`<TwofishXTS key_size=64>`),
    matching the `key_size` property -- unlike `TwofishKey`'s repr, which
    reports bits.

    **The tweak is a position, not a nonce.** Reusing the same `tweak` when
    re-encrypting the same data unit is *correct* -- that is what a
    tweakable mode is for, unlike every IV-taking mode `TwofishKey` exposes
    (where reuse is catastrophic). The misuse case here is the *wrong*
    tweak for a position: silent garbage plaintext, not an error. Do not
    carry the "never reuse an IV" habit over to `tweak=` -- randomizing
    tweaks would silently break interop with any real XTS format, all of
    which use the tweak as a stable data-unit index.

    **VeraCrypt's data unit is always 512 bytes**, regardless of the
    underlying drive's physical sector size (even on 4Kn devices) -- the
    tweak for a given byte offset is `byte_offset // 512`, not the OS's
    reported sector number. A wrong data-unit size is the same
    silent-garbage failure mode as a wrong tweak.

    Args:
        key: 32, 48, or 64 bytes -- one concatenated `key1 || key2` (two
            128/192/256-bit halves; `key1` drives the data cipher, `key2`
            the tweak, per IEEE 1619's Key1‖Key2 ordering). KAT tables that
            list Key1/Key2 separately just concatenate them.

    Raises:
        ValueError: key length not in {32, 48, 64}, or the two halves are
            equal.
    """

    def __new__(cls, key: Buffer) -> Self:
        key1, key2 = _split_xts_key(_coerce_buffer(key, "key"))
        return super().__new__(cls, key1, key2)

    def encrypt(self, data: Buffer, *, tweak: int) -> bytes:
        """Encrypt one data unit.

        `data` is one IEEE 1619 data unit: 16 bytes to 16 MiB (2**20
        blocks). Non-block-multiple lengths are handled via ciphertext
        stealing, so `len(ciphertext) == len(data)` always -- there is no
        padding parameter to misuse.

        Args:
            data: Plaintext (`Buffer`: bytes/bytearray/memoryview).
            tweak: The data-unit number (keyword-only), `0 <= tweak <
                2**128` -- for VeraCrypt, `byte_offset // 512`; for
                dm-crypt/LUKS `plain64`, the sector number. Both real
                formats only ever present tweaks below `2**64`; the full
                128-bit range is IEEE 1619 generality.

        Returns:
            Ciphertext, the same length as `data`.

        Raises:
            ValueError: `data` outside the 16-byte-to-16-MiB data-unit
                range, or `tweak` outside `0 <= tweak < 2**128`.
            TypeError: `tweak` is not an `int` (`bool` counts as `int`).
        """
        return bytes(self._encrypt_raw(_coerce_buffer(data, "data"), _validate_tweak(tweak)))

    def decrypt(self, data: Buffer, *, tweak: int) -> bytes:
        """Decrypt one data unit. See `encrypt` re: data-unit length,
        ciphertext stealing, and `tweak` semantics -- all identical here.

        A wrong `tweak` or wrong data-unit boundary does not raise: XTS is
        unauthenticated, like every other construct in this library, so a
        mismatch silently yields garbage plaintext rather than an error.

        Args:
            data: Ciphertext (`Buffer`).
            tweak: The data-unit number used to encrypt `data` (keyword-only).

        Returns:
            Plaintext, the same length as `data`.

        Raises:
            ValueError: `data` outside the 16-byte-to-16-MiB data-unit
                range, or `tweak` outside `0 <= tweak < 2**128`.
            TypeError: `tweak` is not an `int` (`bool` counts as `int`).
        """
        return bytes(self._decrypt_raw(_coerce_buffer(data, "data"), _validate_tweak(tweak)))


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
    "TwofishXTS",
]
