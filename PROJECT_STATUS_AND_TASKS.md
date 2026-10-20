# libunshield Rust port: status and task ownership

Status snapshot: 2026-10-19, including the real linked-member and Unicode-name follow-ups.

## Goal and current result

Port InstallShield CAB extraction to Rust while preserving the original
libunshield C API/ABI. The original header and all 24 public functions remain
available through shared/static libraries and custom I/O callbacks.

The parser, extractor, native storage, and CLI forbid unsafe Rust. Raw C pointer
and callback operations remain isolated in `src/ffi.rs`; the complete C-compatible
library is not unsafe-free. See [SAFETY.md](SAFETY.md).

Real newer-format installers have now been tested. A format-9 ASUS SoundMAX
package contributes 54 valid CAB members, and a format-21 ASUS Realtek package
contributes 75. Every valid member matches independent original-C metadata and
SHA-256 output. Both pass through Rust and native/custom-callback C callers in
shared, static, and installed libraries on Windows, Ubuntu, and macOS.
The expanded integration passed [CI at e8df8be](https://github.com/H0ttDogg/unshield-rs/actions/runs/39350438927);
evidence is recorded in
[reports/real-installers.md](reports/real-installers.md).

The Kodensha JBeijing7 1.24 update adds format-16 application/dictionary
payloads, a genuine CP932 Japanese filename, and 11 valid previous-file links,
including multi-step chains. All 130 valid members match independent C metadata
and SHA-256 output through Rust and native/callback C shared, static, and installed
libraries on Ubuntu, Windows, and macOS.

Sony SFCard Viewer 2.6.4 adds format 26 with a genuine Japanese UTF-16LE
file-group name referencing six valid members. All 20 valid members match the
independent C reference through Rust and native/callback C shared, static, and
installed libraries on Ubuntu, Windows, and macOS. Its file basenames and directory names are ASCII;
the Unicode evidence is the referenced file-group record. The extended
[three-platform CI passed at 87c495e](https://github.com/H0ttDogg/unshield-rs/actions/runs/39357976354)
with all four packages required. Windows exposed an inventory text-encoding
defect; explicit UTF-8 JSON I/O and a regression test fixed it before this run.

The existing four older upstream datasets still pass all 610 expected output
hashes: Avigo Manager 51, Baldur's Gate patch 132, The Feeble Files Spanish 319,
and Wireplay 108. Combined, this is 889 extracted-file content checks across eight
datasets/packages, not 889 installers.

Differential fuzzing remains deferred.

## Task board

Names assign responsibility and review ownership. Completed automated work does
not imply that a named person has reviewed or signed off on it.

| ID | Task | Responsible | Reviewer | Status and evidence |
| --- | --- | --- | --- | --- |
| T1 | Inventory and result format | Shoib | Farhan | Implemented: URLs, ZIP/CAB hashes, versions, preparation, feature matrix, expectations, and results in `corpus/`. |
| T2 | First real v6-16 installer | Shoib | Farhan | Validated: `asus-soundmax-4570`, format 9, all 54 valid members. |
| T3 | First real v17+ installer | Farhan | Shoib | Validated and reproduced: `asus-realtek-lan-105`, format 21, all 75 valid members. |
| T4 | Repeatable corpus harness | Farhan | Shoib | Implemented: pinned fetch, independent expected JSON, Rust comparison, required-sample enforcement, tooling regression tests. |
| T5 | Real-input C compatibility | Shoib | Farhan | Passed locally and on all three CI platforms: native I/O and callbacks, shared/static/installed libraries, every valid member. |
| T6 | Compatibility fixes discovered by T2-T5 | Shoib | Farhan | No production mismatch found in selected real inputs; no parser/extractor fix needed. Farhan supplies regression tests for future failures. |
| T7 | Cross-platform CI | Farhan | Shoib | Completed: all four required packages passed on Ubuntu/Windows/macOS at `87c495e`, including linked-member and Unicode-group evidence, Rust, CLI list/test, and native/callback shared/static/installed C consumers. Ubuntu independently rebuilt and reproduced the original C reference. |
| T8 | Coverage report | Shoib | Farhan | Written: exact versions/counts, features, failures/skips, commands, and limitations. |
| T9 | Focused callback Miri tests | Farhan | Shoib | Completed in pulled changes: three tests passed on 2026-10-17; original log and linked report retained. |
| T10 | Review FFI assumptions against new tests | Shoib | Farhan | Table copying, userdata lifetime, directory-entry copying, cleanup, callback counts/offsets, and synchronization contract checked; boundary unchanged. Human cross-review pending. |

The first sample milestone is implemented. Cross-review remains a human task;
no approvals are implied by this table.

## Reproducible handoff

| Deliverable | Location | Maintained by |
| --- | --- | --- |
| v6-16 inventory | [corpus/v6-16.json](corpus/v6-16.json) | Shoib |
| v17+ inventory | [corpus/v17-plus.json](corpus/v17-plus.json) | Farhan |
| Independent expected metadata/hashes | `corpus/expected/<sample-id>.json` | Sample task owner |
| Downloaded packages and CAB sets, ignored by Git | `test-data/real-installers/<sample-id>/` | Sample task owner |
| Rust comparison | [tests/real_installers.rs](tests/real_installers.rs) | Farhan |
| Fetch/reference/C comparison tooling | [scripts/real-installers.py](scripts/real-installers.py) | Farhan |
| C extraction, native and callbacks | [tests/reference_members.c](tests/reference_members.c) | Shoib |
| Result matrix and limitations | [reports/real-installers.md](reports/real-installers.md) | Shoib |
| CI and retained logs | [.github/workflows/ci.yml](.github/workflows/ci.yml) | Farhan |

The [corpus guide](corpus/README.md) provides exact fetch, reference-build,
Rust, and shared/static/installed C commands. Expected results must come from
the separately built original C library, pinned at
`cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db`. This repository's `unshield_c`
links to Rust and is only a C-caller compatibility test.

Every new sample needs an ID, product/release, source/retrieval date, installer
and input hashes, complete volumes, preparation instructions, raw version evidence,
independent expected data, and observed features. Record redistribution status
before bundling binaries. Candidate entries may precede validation; recording
expectations requires an explicit sample ID.

## Checks completed locally

- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.
- All 35 Linux Rust integration tests, including all older corpus tests.
- All four newer packages, 279 valid member metadata/size/SHA-256 comparisons.
- Five Python corpus-tool tests, including safe embedded-input preparation.
- Original C reference built independently on Linux; all four packages matched.
- Linux shared/static CTest suites and installed C consumers, including callbacks.
- Separate source-checkout reproduction, fresh CAB preparation, and a new Rust build.
- Linux CLI listing, testing, and extraction for JBeijing7 and SFCard Viewer.

Earlier Windows shared/static/installed checks and the three-platform CI cover
the two ASUS packages. The new JBeijing7 and Sony samples have only been executed on Linux.
See [the report and retained output](reports/real-installers.md).

No new production unsafe code was introduced. The 2026-10-07 partial Miri run
and 2026-10-17 focused callback run are documented in
[miri-check.md](miri-check.md) and
[reports/miri/2026-10-17-callbacks.md](reports/miri/2026-10-17-callbacks.md).
Unsupported subprocess tests and the incomplete allocation-limit Miri run remain
explicit limitations; there is no full-suite Miri pass.

## Divisible follow-up work

The initial real-installer gap is closed for formats 9 and 21. Wider compatibility
still requires additional inputs; one package does not verify a whole version range.

| ID | Next unit of work | Responsible | Reviewer | Completion check |
| --- | --- | --- | --- | --- |
| R1 | Reproduce the other person's sample and review evidence | Shoib and Farhan | Each other | Automated reproduction completed in a separate source checkout with fresh CAB preparation, a new Rust build, original-C comparison, and native/callback C comparisons. Actual human cross-review remains pending. |
| T2-02 | Another producer's v6-16 CAB containing application/driver payloads | Shoib | Farhan | Completed: `kodensha-jbeijing7-124`, format 16, all 130 valid members independently matched; actual application/dictionary payloads. Human review pending. |
| T3-02 | Another producer's v17+ CAB with non-ASCII names | Farhan | Shoib | Completed: `sony-sfcardviewer-264`, format 26, genuine Japanese UTF-16LE file-group name referencing six valid members; all 20 valid members independently matched. File basenames remain ASCII. |
| T2-03 | Real members split across volumes | Shoib | Farhan | A member actually crosses volumes; all pieces preserved and independently matched. |
| T3-03 | Real obfuscated or linked members | Farhan | Shoib | Completed for links: JBeijing7 has 11 valid previous-file links, including chains; raw descriptors recorded and all 130 valid members matched independently. No real obfuscation coverage claimed. |
| T6-N | One reproducible defect per task | Shoib | Farhan | Failing real input, focused regression, fix, original input and existing suite pass. |
| F1 | Differential fuzzing | Deferred | Deferred | Separate later phase, excluded from current work. |

The two ASUS CAB sets contain compressed installer support resources. JBeijing7
adds real payloads, narrow non-ASCII names, and linked members. No selected real
sample contains split or obfuscated members. Sony format 26 adds a Japanese
file-group name; format 21 has only ASCII names. Generated fixtures cover additional features; those are not
substitutes for real-format evidence.

Farhan's implementation and automated validation tasks are complete.
Shoib's T2-03 still needs a real member crossing
volumes. R1 and T10 still require human cross-review. The Windows inventory
encoding defect found in CI is fixed and regression-tested. T6-N applies to
additional reproducible defects; no production parser/extractor mismatch was
discovered in these four packages.
F1 remains deferred.

The Rust CLI is a convenience interface, not an exact reproduction of C CLI
formatting/filtering/encoding. Windows rejects the samples' `<Support>` paths.
Library tests use one output per member index, so every valid member is checked
independently of CLI path normalization or duplicate filenames.
