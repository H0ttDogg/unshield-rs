# Focused callback Miri check

The preserved [raw output](2026-10-17-callbacks.log) records three completed tests
from `tests/callbacks.rs` on 2026-10-17, with no reported undefined behavior or
leaks. The run used:

```sh
cargo +nightly miri test --test callbacks
```

Isolation remained enabled. Small in-memory fixtures exercised copied callback
tables, both custom-open functions, file/directory lifetimes, short reads,
excessive callback counts, and cleanup following open/read/seek/tell/write errors.
The error messages printed by these tests are deliberate failure cases.

This is evidence for three exercised callback paths, not a whole-suite Miri pass
or proof about arbitrary C callers. It does not remove the raw-pointer boundary
in `src/ffi.rs`; [the caller contract](../../SAFETY.md) still applies. No new Miri
run is claimed for the 2026-10-19 corpus integration.
