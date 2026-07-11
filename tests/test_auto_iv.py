"""Tests for RFC 0001's Auto-IV (getrandom; `.iv` contract).

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 13 ("Auto-IV
(getrandom; .iv contract)"). Completes the `@overload` pair on
`TwofishKey.encrypt` the RFC's Proposed Interface always specified:
omitting `iv` auto-generates a fresh 16-byte IV via the OS CSPRNG (the
`getrandom` crate, the RFC's one named Dependency Strategy boundary) and
returns `EncryptResult(iv, ciphertext)`; supplying `iv` explicitly keeps
returning bare `bytes` (slice 8/10's existing, now-regression-tested,
behavior). `TwofishKey.encryptor` gets the same `iv=None` overload for
streaming sessions, with the generated IV readable on `TwofishSession.iv`
-- before *and* after `finalize()` -- so callers can persist it (the
RFC's "`.iv` contract").

**Scope decision (documented, not a silent guess):** the RFC's Contracts
section states plainly that `decrypt`/`decryptor` have "no auto-IV
overload in the RFC" -- decrypting requires the IV the corresponding
encryption used, which cannot be generated after the fact. Both keep
`iv: bytes` as a required keyword-only parameter (unchanged since slices
8/12), so omitting it is a plain Python `TypeError` from argument binding,
not a library-raised error -- there is no dedicated catalog entry for
this because the interpreter itself enforces it.
"""

from typing import Any

import pytest
from oxifish import EncryptResult, Mode, Padding, TwofishKey, TwofishSession

KEY_16 = bytes(range(16))
KEY_32 = bytes(range(32))

# RFC 0002 change 3: introspected from `Mode` rather than hand-enumerated
# (see tests/test_one_shot_modes.py's ALL_MODES/STREAM_MODES comment for the
# general rationale). Every `Mode` member takes an IV today (ECB, the one
# IV-less cipher mode, is deliberately excluded from `Mode` itself -- see
# `Mode`'s docstring in python/oxifish/__init__.py -- and reachable only via
# the separate `ecb_encryptor`/`ecb_decryptor` factories, which this module
# does not test). If a future IV-less member ever joins `Mode`, this list
# picking it up and the resulting round-trip/`.iv` tests failing loudly is
# the desired behavior -- it forces an explicit decision here rather than
# silently exempting the new member.
IV_MODES = list(Mode)


def _padding_for(mode: Mode) -> Padding | None:
    return Padding.PKCS7 if mode == Mode.CBC else None


class TestEncryptAutoIV:
    """`encrypt(iv=None)` (the default) auto-generates a fresh IV via
    `getrandom` and returns `EncryptResult(iv, ciphertext)`."""

    def test_returns_encrypt_result(self) -> None:
        key = TwofishKey(KEY_16)
        result = key.encrypt(b"hello, world! this is a test.")
        assert isinstance(result, EncryptResult)

    def test_iv_is_sixteen_bytes(self) -> None:
        key = TwofishKey(KEY_16)
        result = key.encrypt(b"some plaintext")
        assert isinstance(result.iv, bytes)
        assert len(result.iv) == 16

    def test_round_trips_via_decrypt_with_returned_iv(self) -> None:
        key = TwofishKey(KEY_32)
        plaintext = b"a message that is not block aligned!"
        iv, ciphertext = key.encrypt(plaintext)
        assert key.decrypt(ciphertext, iv=iv) == plaintext

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_round_trips_for_every_iv_mode(self, mode: Mode) -> None:
        key = TwofishKey(KEY_32)
        plaintext = b"twenty-eight-byte-long-message"
        iv, ciphertext = key.encrypt(plaintext, mode, padding=_padding_for(mode))
        assert key.decrypt(ciphertext, mode, iv=iv, padding=_padding_for(mode)) == plaintext

    def test_two_calls_produce_different_ivs(self) -> None:
        key = TwofishKey(KEY_16)
        first = key.encrypt(b"same plaintext, same key")
        second = key.encrypt(b"same plaintext, same key")
        assert first.iv != second.iv

    def test_two_calls_with_same_plaintext_produce_different_ciphertext(self) -> None:
        key = TwofishKey(KEY_16)
        plaintext = b"same plaintext, same key, same everything else"
        first = key.encrypt(plaintext)
        second = key.encrypt(plaintext)
        assert first.ciphertext != second.ciphertext

    def test_many_calls_never_collide(self) -> None:
        key = TwofishKey(KEY_16)
        ivs = {key.encrypt(b"x").iv for _ in range(200)}
        assert len(ivs) == 200

    def test_explicit_iv_still_returns_bare_bytes(self) -> None:
        """Regression: the explicit-IV overload (slices 8/10) must be
        unaffected by adding the auto-IV overload."""
        key = TwofishKey(KEY_16)
        iv = bytes(range(16, 32))
        result = key.encrypt(b"explicit iv path", iv=iv)
        assert isinstance(result, bytes)
        assert not isinstance(result, EncryptResult)

    def test_explicit_iv_is_used_as_is_not_regenerated(self) -> None:
        key = TwofishKey(KEY_16)
        iv = bytes(range(16, 32))
        ciphertext = key.encrypt(b"deterministic with fixed iv", iv=iv)
        # Encrypting again with the same explicit IV must reproduce the
        # exact same ciphertext -- proof the IV was used as-is, not
        # silently regenerated.
        assert key.encrypt(b"deterministic with fixed iv", iv=iv) == ciphertext


class TestDecryptHasNoAutoIV:
    """`decrypt`/`decryptor` keep `iv` a required keyword -- there is no
    RFC auto-IV overload for decryption."""

    def test_decrypt_without_iv_raises_type_error(self) -> None:
        key = TwofishKey(KEY_16)
        ciphertext = key.encrypt(b"anything", iv=bytes(range(16, 32)))
        with pytest.raises(TypeError):
            key.decrypt(ciphertext)  # type: ignore[call-arg]

    def test_decryptor_without_iv_raises_type_error(self) -> None:
        key = TwofishKey(KEY_16)
        with pytest.raises(TypeError):
            key.decryptor()  # type: ignore[call-arg]


class TestEncryptorAutoIV:
    """`encryptor(iv=None)` (the default) auto-generates a fresh IV,
    readable on the returned session's `.iv` -- before *and* after
    `finalize()` (the RFC's "`.iv` contract")."""

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_session_iv_is_sixteen_bytes(self, mode: Mode) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(mode, padding=_padding_for(mode))
        assert isinstance(session.iv, bytes)
        assert len(session.iv) == 16

    def test_iv_readable_before_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR)
        # Accessing .iv before any update()/finalize() call must not raise.
        assert len(session.iv) == 16

    def test_iv_readable_after_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.CTR)
        iv_before = session.iv
        session.finalize(b"some data")
        assert session.iv == iv_before

    def test_iv_stable_across_update_and_finalize(self) -> None:
        key = TwofishKey(KEY_16)
        session = key.encryptor(Mode.OFB)
        iv_before = session.iv
        session.update(b"chunk one")
        assert session.iv == iv_before
        session.finalize(b"chunk two")
        assert session.iv == iv_before

    def test_two_sessions_get_different_ivs(self) -> None:
        key = TwofishKey(KEY_16)
        first = key.encryptor(Mode.CBC, padding=Padding.PKCS7)
        second = key.encryptor(Mode.CBC, padding=Padding.PKCS7)
        assert first.iv != second.iv

    @pytest.mark.parametrize("mode", IV_MODES)
    def test_round_trips_via_decryptor_with_session_iv(self, mode: Mode) -> None:
        key = TwofishKey(KEY_32)
        plaintext = b"streamed message that needs padding maybe"
        padding = _padding_for(mode)

        enc = key.encryptor(mode, padding=padding)
        ciphertext = enc.update(plaintext[:10]) + enc.update(plaintext[10:])
        ciphertext += enc.finalize()

        dec = key.decryptor(mode, iv=enc.iv, padding=padding)
        recovered = dec.update(ciphertext[:10]) + dec.update(ciphertext[10:])
        recovered += dec.finalize()

        assert recovered == plaintext

    def test_explicit_iv_still_used_as_is(self) -> None:
        """Regression: the explicit-IV overload (slice 12) must be
        unaffected by adding the auto-IV default."""
        key = TwofishKey(KEY_16)
        iv = bytes(range(16, 32))
        session = key.encryptor(Mode.CTR, iv=iv)
        assert session.iv == iv

    def test_ecb_sessions_still_have_no_iv(self) -> None:
        """Regression: ECB factories take no `iv` parameter at all and
        are entirely unaffected by this slice."""
        key = TwofishKey(KEY_16)
        session = key.ecb_encryptor(padding=Padding.NONE)
        assert isinstance(session, TwofishSession)
        with pytest.raises(AttributeError):
            _ = session.iv


class TestEncryptResultUnpacking:
    """`EncryptResult` is a `NamedTuple`; auto-IV `encrypt()` results must
    unpack and index the same way regardless of which slice produced
    them."""

    def test_unpacks_as_iv_ciphertext_pair(self) -> None:
        key = TwofishKey(KEY_16)
        result: Any = key.encrypt(b"unpack me")
        iv, ciphertext = result
        assert iv == result.iv
        assert ciphertext == result.ciphertext
