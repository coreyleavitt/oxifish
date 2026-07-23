"""Type stubs for the compiled Rust extension `oxifish._oxifish` (PyO3).

Hand-written -- there is no automatic way to generate a stub for a native
extension module. Mirrors the pyclass/pymethods surface in `src/lib.rs`,
`src/key.rs`, `src/session.rs`, and `src/errors.rs` exactly (parameter
names, kinds, and defaults); verify against those files (or
`python -m mypy.stubtest oxifish._oxifish`) whenever the Rust surface
changes.

This is now the *sole* type source for the compiled module: prior to RFC
0001's code-review round, a co-located `python/oxifish/__init__.pyi`
shadowed `__init__.py` for module resolution (stub files take priority
over same-named `.py` files), which meant `mypy python/ tests/ --strict`
only ever checked that hand-maintained stub, never the actual
implementation -- a drift trap, and the root cause of two of that
review's findings (a stale `finalize` default and a missing `@final`).
`__init__.py` is pure Python, fully annotated (including its `encrypt`
overload pair), and carries `py.typed`, so once *this* file supplies
types for the compiled module it wraps, `__init__.py` needs no `.pyi` of
its own -- the implementation itself becomes the only place its types can
be defined, so it can never again drift from a stub.

Deliberately has no import dependency on `oxifish` (the pure-Python
package that imports *from* this module) to avoid a stub-level import
cycle -- the buffer-accepting parameters below spell out
`bytes | bytearray | memoryview` inline rather than importing the
`Buffer` alias from `oxifish/__init__.py`. (A module-level `Buffer:
TypeAlias = ...` here, mirroring that alias by name, was tried and
rejected: `python -m mypy.stubtest oxifish` correctly flags any
stub-level name with no runtime counterpart, and this compiled module
has no `Buffer` attribute at runtime -- unlike `__init__.py`, where the
alias is a real module-level assignment stubtest can match.)

`TwofishKey` is marked `@disjoint_base` (`typing_extensions`, mirrored by
recent `typing`): PyO3 `#[pyclass(subclass)]` types use a C-level layout
that Python multiple inheritance can't linearize with certain other
bases, which `stubtest` verifies independently of this stub -- omitting
the marker is a real mismatch it flags, not a style nit.
"""

from typing import Final, Literal, Self, final

from typing_extensions import disjoint_base

BLOCK_SIZE: Final[int]

class DecryptionError(ValueError):
    """Uniform padded-decrypt failure. Defined in Rust via
    `pyo3::create_exception!` (`src/errors.rs`); see RFC 0001's Contracts
    section for the normative security scope."""

@final
class TwofishSession:
    """Streaming session object (`src/session.rs`), obtained only via
    `TwofishKey`'s factory methods. `#[pyclass]` without `subclass` in
    Rust -- PyO3 rejects subclassing from Python for such a class, so
    `@final` here reflects a real runtime restriction, not just a style
    preference.
    """

    @property
    def mode(self) -> Literal["cbc", "ctr", "cfb", "ofb", "ecb"]: ...
    @property
    def direction(self) -> Literal["encrypt", "decrypt"]: ...
    @property
    def iv(self) -> bytes:
        """Raises `AttributeError` on ECB sessions (no IV concept); the
        descriptor stays visible in `dir()` regardless (a PyO3
        limitation the RFC explicitly accepts)."""
        ...
    def update(self, data: bytes | bytearray | memoryview) -> bytes: ...
    def finalize(self, data: bytes | bytearray | memoryview | None = None) -> bytes:
        """Runtime default is `None`
        (`#[pyo3(signature = (data=None))]` in `src/session.rs`), not
        `b""` -- `PyBuffer` has no zero-argument constructor to use as a
        signature default, so the Rust side substitutes an empty
        `Vec<u8>` when `data` is omitted. Behaviorally equivalent to a
        `b""` default; the stub says `None` because that is what
        `inspect.signature`/`stubtest` actually observe at runtime."""
        ...
    def __repr__(self) -> str: ...

@disjoint_base
class TwofishKey:
    """New-surface key object (`src/key.rs`). `#[pyclass(subclass)]` in
    Rust -- `oxifish.TwofishKey` (`__init__.py`) subclasses this
    directly, which is why this class is *not* `@final`. The `_*_raw`
    methods below (all private, called only from that subclass) are this
    stub's true typed surface; the public, `Buffer`-coercing API
    (`encrypt`/`decrypt`/`encryptor`/`decryptor`/`ecb_encryptor`/
    `ecb_decryptor`) lives entirely in `oxifish/__init__.py`, which is
    itself fully annotated and therefore needs no stub of its own.
    """

    @property
    def key_size(self) -> int:
        """Key size in bytes (16, 24, or 32)."""
        ...
    def __new__(cls, key: bytes) -> Self:
        """`key` is bytes-only at this boundary (PyO3's `FromPyObject`
        for `&[u8]`) -- the wider `Buffer` union is coerced to `bytes` by
        `oxifish.TwofishKey.__new__` before reaching here."""
        ...
    def _encrypt_raw(
        self,
        data: bytes,
        mode: str,
        iv: bytes | None,
        padding: str | None,
        ctr_width: int | None,
    ) -> tuple[bytes, bytes]:
        """Returns `(iv, ciphertext)`; `iv=None` auto-generates via the
        OS CSPRNG. `ctr_width` is `None` when `oxifish.TwofishKey.encrypt`'s
        own `ctr_width` argument equals its default (128) -- see that
        method's docstring. See `src/key.rs::TwofishKey::_encrypt_raw`."""
        ...
    def _decrypt_raw(
        self,
        data: bytes,
        mode: str,
        iv: bytes,
        padding: str | None,
        ctr_width: int | None,
    ) -> bytes: ...
    def _encryptor_raw(
        self,
        mode: str,
        iv: bytes | None,
        padding: str | None,
        ctr_width: int | None,
    ) -> TwofishSession: ...
    def _decryptor_raw(
        self,
        mode: str,
        iv: bytes,
        padding: str | None,
        ctr_width: int | None,
    ) -> TwofishSession: ...
    def _ecb_encryptor_raw(self, padding: str) -> TwofishSession: ...
    def _ecb_decryptor_raw(self, padding: str) -> TwofishSession: ...
    def __repr__(self) -> str: ...

@disjoint_base
class TwofishXTS:
    """Base pyclass for the XTS surface (`src/xts_py.rs`, RFC 0003 slice
    4). `#[pyclass(subclass)]` in Rust, mirroring `TwofishKey`'s two-layer
    split -- `oxifish.TwofishXTS` (`__init__.py`) subclasses this directly,
    which is why this class is *not* `@final` (see `TwofishKey`'s own doc
    re: `@disjoint_base`, which applies identically here). The `_*_raw`
    methods below are this stub's true typed surface; the public,
    `Buffer`-coercing/key-splitting/tweak-range-validating API (`encrypt`/
    `decrypt`) lives entirely in `oxifish/__init__.py`.
    """

    @property
    def key_size(self) -> int:
        """TOTAL key size in bytes (32, 48, or 64) -- both halves combined,
        matching `TwofishKey.key_size`'s total-bytes meaning."""
        ...
    def __new__(cls, key1: bytes, key2: bytes) -> Self:
        """`key1`/`key2` are bytes-only at this boundary (PyO3's
        `FromPyObject` for `&[u8]`) -- `oxifish.TwofishXTS.__new__` coerces
        the wider `Buffer` union to `bytes`, splits it in half, and checks
        the halves differ *before* reaching here (RFC §2: the equal-halves
        guard is facade-only -- this constructor must accept equal
        halves)."""
        ...
    def _encrypt_raw(self, data: bytes, tweak: int) -> bytes:
        """`tweak` is the already-range-validated (`0 <= tweak < 2**128`)
        data-unit number; `oxifish.TwofishXTS.encrypt` validates the range
        itself so an out-of-range value never reaches here as PyO3's
        generic `OverflowError`. See `src/xts_py.rs::TwofishXTS::_encrypt_raw`."""
        ...
    def _decrypt_raw(self, data: bytes, tweak: int) -> bytes: ...
    def __repr__(self) -> str: ...

# PyO3 auto-populates `__all__` on the compiled module from its
# `m.add_class`/`m.add` registrations (`src/lib.rs`'s `_oxifish` function)
# -- declared here so `stubtest` can match it against the runtime value.
__all__ = ["BLOCK_SIZE", "DecryptionError", "TwofishKey", "TwofishSession", "TwofishXTS"]
