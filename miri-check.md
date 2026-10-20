# Historical Miri check

The 2026-10-07 check used revision `98482a7` and
`rustc 1.101.0-nightly (db8f076d2 2026-10-03)`:

```sh
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri nextest run --no-fail-fast
```

The available [full log](reports/miri/2026-10-07-full.log) and
[partial serial log](reports/miri/2026-10-07-serial-partial.log) are preserved.
Twenty tests completed without reported undefined behavior or leaks. Four CLI
tests encountered unsupported subprocess operations; the allocation-limit test
was stopped before completion after about 49 minutes; five upstream corpus tests
were ignored. This was a partial check, not a clean pass of the full suite.

Custom file/directory callbacks were absent from that run. The later
[2026-10-17 focused run](reports/miri/2026-10-17-callbacks.md) completed three
callback tests. These reports summarize existing evidence and do not claim that
all production paths have been interpreted by Miri.
