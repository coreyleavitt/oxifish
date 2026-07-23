"""RFC 0002 change 4: README python fences execute as real code.

RFC 0002 (docs/rfcs/0002-toolchain-sync.md), audit row 6 / Slice 2
("Executable docs"). Before this slice, README.md's seven ` ```python ```
fences used never-defined placeholders (`derived_key`, `ciphertext`,
`header_iv`, ...) -- copy-pasting any fence in isolation raised
`NameError`, and `--doctest-glob` silently collected zero items since the
README has no `>>>` blocks. The README was rewritten (this slice) under
three probe-derived rules documented in the RFC:

1. A fence whose ciphertext is first consumed by `decrypt()` synthesizes
   that ciphertext via a real `encrypt()` call in the same fence (random
   bytes are essentially never valid padded ciphertext).
2. `Padding.NONE` fences use exact block-multiple plaintext lengths.
3. Only the *first* fence binds `key` -- every later fence reuses it.

Those rules make "copy-paste-runnable" hold only when the document is read
top-to-bottom: mid-document fences intentionally depend on variables
earlier fences defined. This harness proves that contract by executing
fences 0..i in one namespace for parametrized test *i*, so a broken fence
is named by exactly the fence index where the exception was raised --
independent of which parametrized test happens to observe it (a bug in an
early fence fails every later parametrized id too, but each failure's
message still names the one fence whose `exec()` actually raised).

Only ` ```python ``` fences are extracted -- the Installation section's
` ```bash ``` fence and the Development section's ` ```bash ``` fence
(which invokes `pytest` itself) are not Python and must never be
collected here, or this harness would recursively re-invoke pytest.

No output matching: auto-generated IVs make output nondeterministic across
runs, so "correctness" here is defined as "executes without raising", not
as matching a captured transcript.

This module also hosts the IV-reuse guard (`_guard_iv_reuse`) and applies
it beyond the README: `TestModuleDocstringNeverReusesIv` runs
`python/oxifish/__init__.py`'s module-docstring examples under the same
guard, because `--doctest-modules` alone only proves "runs without
raising" and cannot see an example semantically modeling IV reuse.
"""

import doctest
import io
import re
from pathlib import Path

import oxifish as _oxifish_module
import pytest
from oxifish import TwofishKey, TwofishSession

README_PATH = Path(__file__).parent.parent / "README.md"

_PYTHON_FENCE_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)

# Snapshot count (RFC 0003 slice 5: "10 python fences at last count" -- the
# "Modes" section's `ctr_width` paragraph added one). Asserted below so a
# future fence add/remove in README.md fails loudly here instead of the
# per-fence parametrization silently growing/shrinking without anyone
# noticing this harness needs a look.
_EXPECTED_FENCE_COUNT = 10


def _extract_python_fences(readme_text: str) -> list[str]:
    """Extract only ` ```python ``` fence bodies, in document order."""
    return _PYTHON_FENCE_RE.findall(readme_text)


_FENCES = _extract_python_fences(README_PATH.read_text())


def test_readme_has_expected_python_fence_count() -> None:
    assert len(_FENCES) == _EXPECTED_FENCE_COUNT, (
        f"README.md now has {len(_FENCES)} python fences, expected "
        f"{_EXPECTED_FENCE_COUNT} -- a fence was added to or removed from "
        "README.md without updating this count (and, if intentional, "
        "tests/test_readme.py's parametrization/rules commentary should be "
        "reviewed against RFC 0002 change 4's three rewrite rules)"
    )


@pytest.mark.parametrize("fence_index", range(len(_FENCES)))
def test_fence_executes(fence_index: int) -> None:
    """Fences 0..fence_index execute, in order, in one shared namespace --
    mirroring a reader who copy-pastes the document top-to-bottom.

    A failure's message names the exact fence whose code raised, and the
    fix action (edit README.md's fence at that index) -- regardless of
    which parametrized `fence_index` happened to be running when the
    exception surfaced, since an earlier broken fence fails every later
    index too.
    """
    namespace: dict[str, object] = {}
    for i in range(fence_index + 1):
        try:
            # Executing README.md's own fences is this harness's entire
            # purpose (not untrusted input) -- S102 suppressed accordingly.
            exec(  # noqa: S102
                compile(_FENCES[i], f"<README.md python fence #{i}>", "exec"), namespace
            )
        except Exception as exc:
            pytest.fail(
                f"README.md python fence #{i} failed to execute "
                f"({exc.__class__.__name__}: {exc}) -- edit README.md's "
                f"fence #{i} (0-indexed, in document order) to fix it"
            )


# ============================================================================
# IV reuse guard (mechanical check for README's own "Never reuse an iv under
# the same key" rule)
# ============================================================================
#
# The fence-execution tests above only prove each fence *runs*; they don't
# notice a fence quietly reusing an earlier fence's IV for a second,
# different encryption under the same key -- exactly the class of bug that
# rule exists to prevent, and exactly what would go undetected if a future
# edit reintroduced it. This wraps the two low-level, non-overloaded entry
# points `TwofishKey.encrypt`/`.encryptor` route through --
# `_encrypt_raw`/`_encryptor_raw` (see `_oxifish.pyi`) -- rather than the
# public `encrypt`/`encryptor` methods themselves, to sidestep `encrypt`'s
# `@overload` pair: both raw methods return unconditionally (`_encrypt_raw`
# always as `(iv, ciphertext)`, `_encryptor_raw` as a `TwofishSession` whose
# `.iv` is always readable), regardless of whether the caller supplied
# `iv=` or left it to auto-generate, so there is exactly one place per
# method to read "the IV this encryption actually used."
#
# `decrypt`/`decryptor` are deliberately left unwrapped: decrypting with the
# same IV a paired `encrypt`/`encryptor` call used is not reuse (it's
# recovering that same operation's plaintext), so wrapping them would
# produce false positives on every legitimate decrypt example.
#
# The XTS fence (RFC 0003 slice 4, "XTS (disk-volume encryption)") is
# exempt from this guard by construction, not by an explicit carve-out:
# `TwofishXTS.encrypt`/`.decrypt` never call `TwofishKey._encrypt_raw`/
# `_encryptor_raw` -- the two methods wrapped below -- so nothing in that
# fence is ever intercepted here. This is intentional and documented (not
# an oversight the harness "should" catch): XTS has no IV and takes a
# `tweak` instead, which is a data-unit *position* that is correct to
# reuse (RFC §2, "the tweak is a position, not a nonce") -- the opposite
# of the IV-reuse rule this guard exists to enforce, so the guard rightly
# has nothing to say about that fence.


def _record_iv_use(seen: set[tuple[int, bytes]], key: TwofishKey, iv: bytes, label: str) -> None:
    """Record one (key identity, iv bytes) pair, failing if it was already
    used by an earlier encryption in this fence run."""
    marker = (id(key), iv)
    assert marker not in seen, (
        f"IV reuse detected: {label} reused an (key, iv) pair an earlier "
        "encryption in this fence sequence already used -- see README.md's "
        "'Never reuse an iv under the same key' rule"
    )
    seen.add(marker)


def _guard_iv_reuse(monkeypatch: pytest.MonkeyPatch) -> set[tuple[int, bytes]]:
    """Wrap `TwofishKey._encrypt_raw`/`_encryptor_raw` to record every (key
    identity, iv bytes) pair used, failing on reuse. Returns the mutable
    `seen` set so callers can assert it actually recorded something -- an
    empty `seen` after executing code known to encrypt would otherwise mean
    this wrap silently stopped intercepting anything (e.g. `encrypt`/
    `encryptor` rerouted away from the two raw methods wrapped here), and
    `monkeypatch.setattr(..., raising=True)` gives no signal of that on its
    own since the attributes still exist to patch.
    """
    seen: set[tuple[int, bytes]] = set()
    original_encrypt_raw = TwofishKey._encrypt_raw
    original_encryptor_raw = TwofishKey._encryptor_raw

    def guarded_encrypt_raw(
        self: TwofishKey,
        data: bytes,
        mode: str,
        iv: bytes | None,
        padding: str | None,
        ctr_width: int | None,
    ) -> tuple[bytes, bytes]:
        used_iv, ciphertext = original_encrypt_raw(self, data, mode, iv, padding, ctr_width)
        _record_iv_use(seen, self, used_iv, f"encrypt(mode={mode!r})")
        return used_iv, ciphertext

    def guarded_encryptor_raw(
        self: TwofishKey,
        mode: str,
        iv: bytes | None,
        padding: str | None,
        ctr_width: int | None,
    ) -> TwofishSession:
        session = original_encryptor_raw(self, mode, iv, padding, ctr_width)
        _record_iv_use(seen, self, session.iv, f"encryptor(mode={mode!r})")
        return session

    monkeypatch.setattr(TwofishKey, "_encrypt_raw", guarded_encrypt_raw)
    monkeypatch.setattr(TwofishKey, "_encryptor_raw", guarded_encryptor_raw)
    return seen


def _assert_guard_exercised(seen: set[tuple[int, bytes]], context: str) -> None:
    """Self-check shared by every `_guard_iv_reuse` consumer: the guarded
    code is known to encrypt, so an empty `seen` means the monkeypatch wrap
    on `TwofishKey._encrypt_raw`/`_encryptor_raw` silently stopped
    intercepting anything (e.g. `encrypt`/`encryptor` rerouted away from
    those raw methods while leaving them defined, so
    `monkeypatch.setattr(raising=True)` still succeeds). Centralized so the
    fix-action clause cannot drift out of any call site's message.
    """
    assert seen, (
        "tests/test_readme.py's _guard_iv_reuse recorded zero (key, iv) "
        f"pairs while {context}, which is known to encrypt -- the wrap on "
        "TwofishKey._encrypt_raw/_encryptor_raw is no longer being "
        "exercised (e.g. encrypt()/encryptor() were rerouted away from "
        "those raw methods) -- fix _guard_iv_reuse in tests/test_readme.py "
        "to wrap whatever method the new code path actually calls"
    )


@pytest.mark.parametrize("fence_index", range(len(_FENCES)))
def test_fence_execution_never_reuses_iv(fence_index: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fences 0..fence_index must not encrypt two different things under
    the same (key, iv) pair. Kept separate from `test_fence_executes` so a
    reuse failure reads as its own unambiguous assertion, not a generic
    `exec()` exception.
    """
    seen = _guard_iv_reuse(monkeypatch)
    namespace: dict[str, object] = {}
    for i in range(fence_index + 1):
        # Same justification as test_fence_executes: exec'ing README.md's
        # own fences is this harness's entire purpose.
        exec(  # noqa: S102
            compile(_FENCES[i], f"<README.md python fence #{i}>", "exec"), namespace
        )

    # Fence #0 ("One-shot (the hot path)") always calls `key.encrypt(...)`
    # with no `iv=`, and every parametrized `fence_index` executes fences
    # 0..fence_index inclusive, and fence #0 is known to call
    # key.encrypt() -- so `seen` must be non-empty here for every index.
    _assert_guard_exercised(seen, f"executing README.md fences 0..{fence_index}")


class TestIvReuseGuardCatchesReuse:
    """Fail-first proof, kept permanently (not a scratch test deleted after
    manual verification): the committed version of round 1's one-off proof
    that `_guard_iv_reuse`'s wrap actually intercepts real encryption calls.

    `test_fence_execution_never_reuses_iv`'s `assert seen` above only
    proves the wrap *ran* -- it does not prove the wrap would catch an
    actual reuse (a wrap that recorded a use but never compared it against
    prior uses would also leave `seen` non-empty). This runs a deliberately
    IV-reusing snippet -- never README.md's own fences, which must stay
    reuse-free -- directly under the guard and asserts the reuse is
    caught, mirroring `tests/test_enum_sync.py`'s `TestAnchoringMatters`
    (a fail-first proof of a check's detection power, not just its
    plumbing).
    """

    def test_guard_raises_on_deliberate_iv_reuse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen = _guard_iv_reuse(monkeypatch)
        key = TwofishKey(bytes(range(16)))
        iv = bytes(range(16, 32))
        key.encrypt(b"first message", iv=iv)
        with pytest.raises(AssertionError, match="IV reuse detected"):
            key.encrypt(b"second, different message", iv=iv)
        _assert_guard_exercised(seen, "making two explicit key.encrypt(iv=iv) calls")


# ============================================================================
# Docstring IV reuse guard (N3: mechanical check for the module docstring)
# ============================================================================
#
# `pytest --doctest-modules python/oxifish` only proves python/oxifish/
# __init__.py's module docstring `>>>` examples run without raising -- it
# says nothing about IV reuse, so reintroducing the round-1 IV-reuse bug
# into the docstring (e.g. passing `iv=iv` a second time in the
# `Padding.NONE` example) would pass --doctest-modules silently. This runs
# the same doctest examples a second time, under the same
# `_guard_iv_reuse` wrap the README fences use above, adding the missing
# reuse dimension without touching the existing --doctest-modules CI path.


def _run_module_docstring_doctests(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[doctest.TestResults, str, set[tuple[int, bytes]]]:
    """Run every doctest in `oxifish`'s module docstring under
    `_guard_iv_reuse`, returning the aggregate pass/fail counts, the
    runner's captured text output (so a caller can tell an IV-reuse
    failure from an ordinary doctest output mismatch), and the guard's
    `seen` set."""
    seen = _guard_iv_reuse(monkeypatch)
    finder = doctest.DocTestFinder()
    tests = [t for t in finder.find(_oxifish_module) if t.examples]
    output = io.StringIO()
    runner = doctest.DocTestRunner()
    total_failed = 0
    total_attempted = 0
    for test in tests:
        result = runner.run(test, out=output.write)
        total_failed += result.failed
        total_attempted += result.attempted
    return doctest.TestResults(total_failed, total_attempted), output.getvalue(), seen


class TestModuleDocstringNeverReusesIv:
    def test_module_docstring_examples_never_reuse_iv(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        results, output, seen = _run_module_docstring_doctests(monkeypatch)

        # Checked first and separately from the generic failure count below
        # so an IV-reuse regression reads as its own unambiguous assertion,
        # not a generic doctest-output-mismatch failure.
        assert "IV reuse detected" not in output, (
            "python/oxifish/__init__.py's module docstring reuses an (key, "
            "iv) pair across two encryptions -- see README.md's 'Never "
            "reuse an iv under the same key' rule -- fix the offending "
            f"example in the docstring. Doctest output:\n{output}"
        )
        assert results.failed == 0, (
            f"{results.failed} of {results.attempted} doctest example(s) in "
            "python/oxifish/__init__.py's module docstring failed under "
            "tests/test_readme.py's IV-reuse guard wrap (not an IV-reuse "
            "failure -- see output below) -- fix the docstring example(s). "
            f"Doctest output:\n{output}"
        )
        # The docstring's first example is known to call key.encrypt(); an
        # empty `seen` also covers the collected-zero-examples inert case
        # (which would trivially satisfy the two asserts above).
        _assert_guard_exercised(
            seen,
            "running python/oxifish/__init__.py's module docstring doctests "
            f"({results.attempted} example(s) attempted)",
        )
