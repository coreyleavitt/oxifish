"""RFC 0002 change 3: `Mode`/`Padding` value-set sync pins.

RFC 0002 (docs/rfcs/0002-toolchain-sync.md), audit row 5 / Slice 1 ("Enum
single-representation + pins"). Before this slice, `Mode`/`Padding`'s value
set had **three** independently-drifting encodings on the Rust side: the
`parse_mode`/`parse_padding` match arms in `src/key.rs`, the hand-typed
`"expected one of '…'"` message literal in each catch-all arm, and the
Python `Mode`/`Padding` `StrEnum`s themselves -- a new arm or enum member
that missed a sibling would pass every existing gate silently.

`src/key.rs` now derives all three from a single `(variant, catalog
string)` const table per enum (`ModeSelector::ALL`, `PADDING_TABLE`); the
match arms and the error message text can no longer disagree because they
are no longer separately-authored. This module pins the *observable*
consequence of that collapse from the Python side, two ways:

1. **Enum <-> match arms:** every `Mode`/`Padding` member must actually be
   accepted by the Rust parser -- proven by round-tripping a real
   encrypt/decrypt call for each member, not just checking it doesn't
   raise (a member accepted by the parser but silently mishandled
   downstream would still fail a round-trip).
2. **Enum <-> error message:** the live `"expected one of '…'"` message's
   valid set, parsed with an *anchored* regex (`expected one of (.+)$`,
   then `'([^']+)'` over just that captured tail -- never the whole
   message), must equal `{member.value for member in Mode}` /
   `...Padding`. The anchor is load-bearing: a naive all-quotes
   `re.findall` over the *entire* message also sweeps in the probe's own
   bogus value (e.g. `invalid mode 'ecb-probe': expected one of ...`) and
   the resulting set can then never equal the enum's, even when the
   catalog and the message genuinely agree -- see this module's
   `test_naive_unanchored_parse_would_be_poisoned_by_the_probe_value`
   below, which pins that failure mode directly rather than leaving it as
   an unverified claim in the RFC text.
"""

import re

import pytest
from oxifish import Mode, Padding, TwofishKey

KEY = bytes(range(16))
IV = bytes(range(16, 32))
# Block-aligned so it round-trips unchanged under every `Padding` member,
# `NONE` included (RFC 0002 change 3's round-trip pin covers `Padding` too,
# unlike test_one_shot_cbc.py's CBC-only suite which deliberately excludes
# `Padding.NONE` for its own, unrelated unaligned-plaintext reasons).
PLAINTEXT = bytes(range(32))


class TestModeRoundTrip:
    """Every `Mode` member is accepted by `parse_mode` and actually
    round-trips -- proves enum members correspond 1:1 to the Rust match
    arms `ModeSelector::ALL` now derives `parse_mode` from."""

    @pytest.mark.parametrize("mode", list(Mode))
    def test_every_mode_member_round_trips(self, mode: Mode) -> None:
        key = TwofishKey(KEY)
        ciphertext = key.encrypt(PLAINTEXT, mode, iv=IV)
        assert key.decrypt(ciphertext, mode, iv=IV) == PLAINTEXT


class TestPaddingRoundTrip:
    """Every `Padding` member is accepted by `parse_padding` and actually
    round-trips -- proves enum members correspond 1:1 to `PADDING_TABLE`."""

    @pytest.mark.parametrize("padding", list(Padding))
    def test_every_padding_member_round_trips(self, padding: Padding) -> None:
        key = TwofishKey(KEY)
        ciphertext = key.encrypt(PLAINTEXT, iv=IV, padding=padding)
        assert key.decrypt(ciphertext, iv=IV, padding=padding) == PLAINTEXT


def _anchored_valid_set(message: str) -> set[str]:
    """The anchored parse contract (RFC 0002 change 3): only the tail after
    literal "expected one of " is scanned for quoted values -- never the
    whole message, which would also contain the caller's bogus input."""
    m = re.search(r"expected one of (.+)$", message)
    assert m is not None, f"message has no 'expected one of' tail: {message!r}"
    return set(re.findall(r"'([^']+)'", m.group(1)))


class TestModeErrorMessageMatchesEnum:
    """The live `invalid mode '<value>': expected one of '…'` message's
    valid set must equal `Mode`'s value set -- proves the enum matches the
    error message `parse_mode` builds from `ModeSelector::ALL`, not just
    the match arms (round-trip above already covers those)."""

    def test_valid_set_matches_mode_enum(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError) as exc_info:
            key.encrypt(b"data", "bogus-mode-probe", iv=IV)
        valid = _anchored_valid_set(str(exc_info.value))
        expected = {member.value for member in Mode}
        assert valid == expected, (
            f"the live 'expected one of' message's valid set {sorted(valid)} "
            f"(derived from src/key.rs's ModeSelector::ALL catalog table) does "
            f"not match python/oxifish/__init__.py's Mode enum value set "
            f"{sorted(expected)} -- add/remove the missing member in whichever "
            "of ModeSelector::ALL (src/key.rs) or Mode (python/oxifish/__init__.py) "
            "is out of sync with the other"
        )


class TestPaddingErrorMessageMatchesEnum:
    """See `TestModeErrorMessageMatchesEnum`; same contract for `Padding`."""

    def test_valid_set_matches_padding_enum(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError) as exc_info:
            key.encrypt(b"data", iv=IV, padding="bogus-padding-probe")
        valid = _anchored_valid_set(str(exc_info.value))
        expected = {member.value for member in Padding}
        assert valid == expected, (
            f"the live 'expected one of' message's valid set {sorted(valid)} "
            f"(derived from src/key.rs's PADDING_TABLE catalog table) does not "
            f"match python/oxifish/__init__.py's Padding enum value set "
            f"{sorted(expected)} -- add/remove the missing member in whichever "
            "of PADDING_TABLE (src/key.rs) or Padding (python/oxifish/__init__.py) "
            "is out of sync with the other"
        )


class TestAnchoringMatters:
    """Fail-first proof, kept permanently (not a scratch test deleted after
    manual verification): a naive unanchored `re.findall(r"'([^']+)'",
    message)` over the *whole* message sweeps in the probe's own bogus
    value, so the resulting set can never equal the enum's -- even when the
    catalog and the message genuinely, correctly agree. This is why
    `_anchored_valid_set` above scopes its quote-extraction to the
    "expected one of " tail only."""

    def test_naive_unanchored_parse_is_poisoned_by_the_probes_own_value(self) -> None:
        key = TwofishKey(KEY)
        with pytest.raises(ValueError) as exc_info:
            key.encrypt(b"data", "bogus-mode-probe", iv=IV)
        message = str(exc_info.value)

        naive_valid = set(re.findall(r"'([^']+)'", message))
        anchored_valid = _anchored_valid_set(message)
        expected = {member.value for member in Mode}

        assert "bogus-mode-probe" in naive_valid, (
            f"naive_valid {sorted(naive_valid)} does not contain the probe's own "
            "bogus value -- this proof depends on the unanchored `re.findall` "
            "sweeping in the caller's input from the live error message; if the "
            "message format changed, update _anchored_valid_set's regex and this "
            "test together in tests/test_enum_sync.py"
        )
        assert naive_valid != expected, (
            f"naive_valid {sorted(naive_valid)} unexpectedly equals Mode's value "
            f"set {sorted(expected)} (python/oxifish/__init__.py) -- the whole "
            "point of this proof is that the unanchored parse can never agree "
            "with the enum even when src/key.rs's ModeSelector::ALL and the enum "
            "genuinely match; if this now passes, the probe value itself "
            "('bogus-mode-probe') coincidentally collided with a real Mode "
            "member and needs to change"
        )
        assert anchored_valid == expected, (
            f"the anchored valid set {sorted(anchored_valid)} (derived from "
            f"src/key.rs's ModeSelector::ALL catalog table) does not match "
            f"python/oxifish/__init__.py's Mode enum value set {sorted(expected)} "
            "-- add/remove the missing member in whichever of ModeSelector::ALL "
            "(src/key.rs) or Mode (python/oxifish/__init__.py) is out of sync "
            "with the other"
        )
