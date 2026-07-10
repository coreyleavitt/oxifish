# oxifish

Python bindings (PyO3/maturin) for the RustCrypto Twofish block cipher. Rust core in `src/lib.rs`, Python package in `python/oxifish/`, tests in `tests/`. Build with `uv sync` (runs maturin); test with `uv run pytest` and `cargo test`.

Active RFCs live in `docs/rfcs/`, each with a `.handoff.md` tracking pipeline state.

## Compact Instructions
When compacting, preserve in the summary: the active RFC and its handoff-doc path, the current stage/round, slices done vs remaining, open forks awaiting me, and the exact resume command. After compacting, re-read the handoff doc and MEMORY.md before continuing.
