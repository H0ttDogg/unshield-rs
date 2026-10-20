# unshield-rs

Rust port of [twogood/unshield](https://github.com/twogood/unshield), pinned to
`cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db` (version 1.6.2).
Reads **InstallShield cabinets**, including the version-5 and version-6+ layouts.
Microsoft CAB files are a separate format and are rejected.

The main deliverable is a replacement **C library**. The original
[`libunshield.h`](include/libunshield.h) is included unchanged, and all 24 public
functions are exported under their original names. C callers continue to use
`Unshield *`, the original file-group/component structs, `bool`, `size_t`, and the
original I/O callback table. Rust builds an `rlib`, a shared library, and a static
library. Parsing, extraction, native I/O, and deobfuscation forbid unsafe Rust;
raw C pointers and callback calls are confined to `src/ffi.rs`.
Narrow C filesystem paths preserve raw bytes on Unix and use the Windows ANSI
codepage on Windows, matching the original `fopen` interface.

## Build

Requires Rust 1.88+ and a native linker. On Windows, use an MSVC developer shell.
If this workspace's local toolchain is present, `scripts/cargo.ps1` selects it.

```sh
cargo build --release --lib
cargo build --release --bin unshield-rs
```

Direct Cargo output:

| Platform | Shared library | Static library |
| --- | --- | --- |
| Linux | `target/release/libunshield.so` | `target/release/libunshield.a` |
| macOS | `target/release/libunshield.dylib` | `target/release/libunshield.a` |
| Windows MSVC | `target/release/unshield.dll` + `unshield.dll.lib` | `target/release/unshield.lib` |

Use **CMake for installation or replacement of already-linked applications**;
it sets the upstream major-version identity (`libunshield.so.1` on Linux,
`libunshield.1.dylib` on macOS), installs the header, and supplies `libunshield.pc`
and the `unshield::libunshield` CMake target:

```sh
cmake -S . -B build -DBUILD_TESTING=OFF
cmake --build build --config Release
cmake --install build --config Release --prefix /your/prefix
```

For static installation, configure with `-DBUILD_STATIC=ON`. Static consumers
also need the platform's Rust runtime system libraries; the CMake target includes
them. Shared-library callers do not need Rust installed at runtime.

```c
#include <libunshield.h>

Unshield *archive = unshield_open("data1.cab");
if (archive) {
    for (int i = 0; i < unshield_file_count(archive); ++i) {
        if (unshield_file_is_valid(archive, i)) {
            /* Pass NULL to test extraction without writing a file. */
            bool ok = unshield_file_save(archive, i, NULL);
            /* Handle ok before continuing. */
            (void)ok;
        }
    }
    unshield_close(archive);
}
```

`unshield_file_save_old` selects the legacy compressor; `unshield_file_save_raw`
returns deobfuscated payload without decompression. Supplied I/O callbacks serve
both input and output. The callback table is copied during open; userdata must
remain valid until close. On Windows, `readdir` must return the layout from
upstream's `win32_msvc/dirent.h`; on Unix it uses the native `struct dirent` ABI.
As in upstream, callback seek offsets use C `long`, including its Windows limits.

Names and file-group pointers remain valid until `unshield_close`. Callers must
not free borrowed pointers and must synchronize operations on a handle. C errors
return NULL, false, zero, or -1 as appropriate. Rust panics are caught at the C
boundary; ordinary errors follow the configured log level.

## Implemented behavior

- `.hdr` metadata with fallback to embedded `.cab` metadata; case-insensitive
  numbered-volume lookup using upstream's filename-prefix convention.
- Files, directories, file groups, and component-to-group relationships.
- 32-bit legacy descriptors and 64-bit descriptors/volume offsets for v6+.
- UTF-16LE names for v17+; original pre-Unicode name bytes preserved through C.
- Uncompressed files, length-prefixed raw DEFLATE chunks, legacy marker-delimited
  chunks, and the legacy embedded-marker workaround.
- Split members across volumes, continuous deobfuscation, previous-file links,
  external legacy files, and missing-marker repair for external files.
- Expanded-size checks, and embedded MD5 checks in new mode for v6+, matching
  upstream's checksum policy. Legacy/raw modes do not add an MD5 requirement.

The Rust CLI supports `c`, `g`, `l`, `t`, `x`, `-O`, `-r`, `-d`, `-c`, `-g`,
`-i`, `-j`, `-L`, `-R`, `-D`, and `-V`. It accepts exact member-name filters.
It is a convenience CLI: output formatting, name normalization, wildcard filters,
and `-e` encoding conversion are not a full reproduction of the C CLI. For exact
original CLI behavior, compile the **unchanged upstream C CLI** against this
library (`-DTEST_UPSTREAM_CLI=ON` builds a validation executable).

The library leaves output paths under caller control, as the C API does. The Rust
CLI rejects traversal, absolute member paths, and existing symlinks in member
output paths. It assumes the extraction directory is not changed concurrently.
Malformed metadata can be rejected earlier than in C. Metadata is capped at
64 MiB and 1,000,000 directory/file entries; legacy compressed chunks are capped
at 1 MiB. Streaming extraction does not truncate file sizes to 32 bits.
`Archive::extract` limits in-memory output to 512 MiB; use `extract_to` for larger
members. A failed save may leave partial output, matching the C API.

## Validation

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The self-contained tests generate cabinets for versions 0, 5, 6, 7, 13, 17, and
20. They exercise compression, Unicode, MD5 failures, raw extraction,
deobfuscation/seed wraparound, split chunk prefixes, callback-compatible pointer
lifetimes, invalid indices, truncated metadata, and cycles.
They also test empty members, linked members, embedded metadata, legacy name
bytes, and 64-bit member/volume offsets above 4 GiB without allocating huge files.

Real upstream corpus tests are opt-in; no installer binaries are vendored here:

```sh
sh scripts/fetch-upstream.sh                 # PowerShell: scripts/fetch-upstream.ps1
cargo test --test corpus -- --include-ignored --nocapture
cmake -S . -B build -DTEST_UPSTREAM_CLI=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Verified locally on Windows x64/MSVC:
- All **610** upstream manifest hashes: Avigo Manager (51), Baldur's Gate patch
  (132), The Feeble Files Spanish (319), Wireplay (108).
- The historical CVE-2015-1386 traversal fixture is rejected by the Rust CLI.
- A compiled C harness calls every public API, compares extracted bytes, uses
  custom file/directory callbacks, and checks that opens and closes balance.
- The original C CLI builds without source edits and tests a generated v6 CAB.
- Shared and static CMake builds, installation, and a separate C consumer of the
  installed `find_package(unshield)` target pass.

Real newer-format validation includes two vendor-distributed ASUS packages:
**format 9** SoundMAX (54 valid CAB members) and **format 21** Realtek (75).
All **129 valid members** match independently extracted upstream C metadata and
SHA-256 hashes. The same comparisons pass through native C I/O and custom
callbacks in shared, static, and installed libraries on Windows, Ubuntu, and
macOS. See
[the inventory and reproduction commands](corpus/README.md) and
[the measured coverage report](reports/real-installers.md). Fetch and compare them:

```sh
python3 scripts/real-installers.py fetch
cargo test --locked --test real_installers -- --nocapture
```

Format 21 uses UTF-16LE storage, but neither sample contains non-ASCII names.
A third vendor package, **JBeijing7 1.24 (format 16)**, adds **130 valid
members**, application/dictionary payloads, a genuine Japanese CP932 filename,
and **11 previous-file links**, including chains. Every member matches the
independent C reference through Rust and native/callback C shared, static, and
installed consumers on Linux. Corpus preparation reads hash-pinned byte ranges
without executing its installer.

A fourth package, **Sony SFCard Viewer 2.6.4 (format 26)**, adds a genuine
Japanese UTF-16LE file-group name referencing six valid members. All **20**
valid members match independent C metadata and SHA-256 output through Rust and
native/callback C shared, static, and installed libraries on Linux. Member
basenames and directories are ASCII; the non-ASCII evidence is the actual group
name. Combined coverage is **889** file content checks across eight datasets/packages.

Non-ASCII member basenames and real split/obfuscated member coverage remain open.
CI requires all four packages on Linux, macOS, and Windows, including C callbacks,
and rebuilds the independent reference on Ubuntu. The two added samples' CI execution
is pending; the report distinguishes it from the existing two-package CI run.
Compatibility
is tied to the pinned header/API; this is not a claim of exhaustive compatibility
with every InstallShield producer or undocumented format variant.

Differential fuzzing is intentionally deferred.

The [project status and task board](PROJECT_STATUS_AND_TASKS.md) separates
completed implementation/validation from further corpus work and human review.

### Miri

The 2026-10-07 Miri check at commit `98482a7`, using
`rustc 1.101.0-nightly (db8f076d2 2026-10-03)`, found **no undefined behavior in
20 completed tests** and reported no memory leaks. The run used
`cargo +nightly miri nextest run --no-fail-fast` with
`MIRIFLAGS="-Zmiri-disable-isolation"` to allow temporary-file access.
It exercised C ABI name and struct lifetimes, mutable group records, overlapping
deobfuscation arguments, and preservation of legacy filename bytes.

This was a partial check, not a passing run of the entire suite:

- Four CLI tests could not run because Miri does not support the subprocess call
  `posix_spawnattr_init`; these are unsupported operations, not UB findings.
- The metadata allocation-limit test was stopped before completion after about
  49 minutes.
- Five upstream corpus tests were ignored because the corpus was not present.
- Custom I/O callbacks through `unshield_open2` and
  `unshield_open2_force_version` were not exercised by that run. A subsequent
  focused run covers these paths, as described below.

A clean Miri result applies only to the code paths exercised. See
[miri-check.md](miri-check.md) for that historical report. Its original available
[full log](reports/miri/2026-10-07-full.log) and
[partial serial log](reports/miri/2026-10-07-serial-partial.log) are preserved.

A focused run on 2026-10-17 completed **three new custom-callback tests** without
reported undefined behavior or leaks. They exercise copied callback tables,
file/directory lifetimes, short reads, and failure cleanup using small in-memory
fixtures, with Miri isolation enabled:

```sh
cargo +nightly miri test --test callbacks
```

See [the focused report and raw output](reports/miri/2026-10-17-callbacks.md) and
[SAFETY.md](SAFETY.md) for remaining limits and the C caller contract. This is
additional path coverage, not a full-suite Miri pass.

## License

MIT; the upstream copyright notice is retained in [LICENSE](LICENSE).
