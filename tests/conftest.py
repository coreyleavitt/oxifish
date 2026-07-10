"""Shared pytest/Hypothesis configuration.

RFC 0001 (docs/rfcs/0001-twofish-session-api.md), Slice 14 ("Hypothesis
chunking-invariance suite (budgeted; CI profile)"). Registers Hypothesis
profiles so the RFC's stated per-combo budget
(`st.binary(max_size=200)` data, `max_examples=25`, `deadline=None`) is
the *active default* -- a plain `pytest`/CI invocation with no extra
flags stays fast, matching the Testing Strategy section's stated purpose
("keep CI fast"). A `"thorough"` profile is also registered, opt-in via
`--hypothesis-profile=thorough` or `HYPOTHESIS_PROFILE=thorough`, for
digging deeper locally when investigating a shrunk failure. A `"ci"`
profile identical to the budget is registered too, so a future CI
workflow change can select it explicitly by name without this file
changing again.
"""

from hypothesis import settings

_BUDGET_EXAMPLES = 25

settings.register_profile("default", max_examples=_BUDGET_EXAMPLES, deadline=None)
settings.register_profile("ci", max_examples=_BUDGET_EXAMPLES, deadline=None)
settings.register_profile("thorough", max_examples=500, deadline=None)

settings.load_profile("default")
