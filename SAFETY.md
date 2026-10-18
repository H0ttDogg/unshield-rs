# Safety boundaries and review

The parser, extractor, native storage module, path validation, deobfuscation, and
Rust CLI forbid unsafe Rust. The library denies unsafe code by default and permits
it only in `src/ffi.rs`; unsafe operations inside unsafe functions still require
explicit blocks. This policy covers this project's source, not the internals of
the Rust standard library or dependencies.

The complete C-compatible library is **not unsafe-free**. Its existing ABI uses
raw handles, C strings, mutable buffers, and function pointers. Accessing those
objects requires an unsafe boundary. Windows narrow-path conversion also uses
Win32 calls in that boundary. Moving these operations into another dependency or
into C would not remove their safety requirements.

## C caller contract

- Pass live, correctly aligned objects of the declared types and NUL-terminated
  strings. Buffer sizes must describe accessible memory. A non-null pointer's
  validity cannot be established by the library.
- Close each handle once and synchronize operations on a handle. Borrowed names
  and group records remain valid until close; do not free them. Strings are
  read-only. Mutable group records use `UnsafeCell`, and name/find accessors observe
  edits. A replacement name must remain a live C string until replaced or closed.
- Callback tables are copied. Userdata and callback functions must remain valid
  for the handle's lifetime. Callbacks obey the corresponding stdio/dirent
  contracts, including buffer capacities and directory-entry lifetime/layout.
  They must not retain temporary buffers, unwind, or close/re-enter a handle in use.
- The deobfuscation seed can overlap its byte buffer: the implementation reads
  the seed into a local value and writes it back after processing, as upstream does.
- Ordinary errors return the original API's failure values. Rust panics are caught
  at entry points under the default unwind profile. Process aborts, allocation
  failure, invalid C pointers, and panicking C callbacks are not recoverable errors.

## Archive and filesystem limits

Metadata offsets and record extents are checked before access, including on
32-bit targets. The declared header extent is capped at 64 MiB. Parsing applies a
128 MiB decoded-metadata budget, a 64 KiB encoded-string limit, and an entry-count
limit of 1,000,000. The budget is a parsing policy, not a bound on total process
memory: allocator overhead, temporary vectors, and FFI copies also use memory.

Streaming extraction checks expanded lengths, chunk limits, and the format's
applicable MD5 checksum. These checks detect corruption; MD5 is not authentication.
Streaming has no total output/disk/time quota. Callers handling arbitrary installers
must set their own resource policy. `Archive::extract` caps in-memory output at
512 MiB. Legacy/raw extraction retains upstream's checksum policy.

The C API and `Archive::save` accept caller-chosen output paths and may leave
partial output on extraction failure. They validate the selected member and open
its input before opening the output. The CLI validates archived paths, rejects
existing symlinks and Windows reparse points, and only replaces the destination
after extraction succeeds. It uses a new temporary file, so existing hardlinks
cannot cause another file to be overwritten. Windows device names and path
normalization ambiguities are rejected.

The extraction directory must not be concurrently modified by another process.
Path checks are not a filesystem sandbox. Legacy external-file lookup also uses
caller-provided storage and is not confined against preexisting symlinks.

## Review coverage

The October 2026 review covered every production Rust module, the public header,
build/install configuration, CI, scripts, and test harnesses. It found and repaired
output truncation/deletion on failure, mutable-C-record aliasing, overlapping
deobfuscation arguments, insufficient metadata bounds/allocation limits, trailing
compressed data acceptance, empty legacy member handling, lossy native filename
lookup, overlapping group selection, and pkg-config installation/linking metadata.
The final volume review also removed a legacy sentinel collision with a valid
split-member offset in newer cabinets; sparse-file tests cover that boundary.

Regression tests are in `tests/review.rs`. The original generated CAB tests,
610 upstream manifest hashes, historical traversal fixture, compiled C ABI
harness, original C CLI, and installed C consumer remain part of validation.
CI covers Ubuntu, Windows, and macOS, including shared/static C callers and a
relocated multiarch pkg-config static consumer on Ubuntu.

This review and passing tests are not proof of an absence of bugs. Newer real
coverage now includes one format-21 installer CAB set, with all 75 valid members
compared against independent C metadata and SHA-256 hashes on Linux. Other newer
versions and non-ASCII/split/obfuscated/linked real inputs remain unverified;
see [the coverage report](reports/real-installers.md).
Three small in-memory callback tests also pass under Miri; see
[the focused report](reports/miri/2026-10-17-callbacks.md). This checks exercised
callback operations, not arbitrary C caller behavior. Differential fuzzing
remains deferred.
