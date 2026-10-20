# Real installer corpus

Five packages supply real InstallShield format-6, format-9, format-16, format-21, and format-26 CAB sets.
These are downloaded archives; tests never execute their installers. Binaries
remain in ignored `test-data/real-installers/` because redistribution permission
has not been established.

| Inventory | Sample ID | Format | Valid members |
| --- | --- | ---: | ---: |
| [v6-16.json](v6-16.json) | `asus-soundmax-4570` | 9 | 54 |
| [v17-plus.json](v17-plus.json) | `asus-realtek-lan-105` | 21 | 75 |
| [v6-16.json](v6-16.json) | `kodensha-jbeijing7-124` | 16 | 130 |
| [v17-plus.json](v17-plus.json) | `sony-sfcardviewer-264` | 26 | 20 |
| [v6-16.json](v6-16.json) | `epson-twain-571a` | 6 | 170 |

JBeijing7 contains application/dictionary payloads, a genuine Japanese CP932
filename, and 11 valid members with previous-file links, including multi-step
chains. It supplies real linked-member coverage and another producer's v6-16
payloads. Format 16 does not establish v17+ non-ASCII UTF-16LE name coverage.

SFCard Viewer provides that newer-format name evidence in the real file-group
record `ｱﾌﾟﾘｹｰｼｮﾝ実行可能ﾌｧｲﾙ`, which references six valid members. Every
member basename and directory name is ASCII; the tested non-ASCII string is the
group name. The inventory records its exact UTF-8 representation and valid
member indices. An archived official download is used because the original
live URL now redirects to a web page.

Epson TWAIN 5.71A (Rev.F) supplies four physical split members across volumes
2/3, 3/4, 4/5, and 5/6. Its self-extracting ZIP is read without execution;
all six CAB volumes and the header are retained. `split_evidence` pins each
member's segment offsets and stored byte counts. Tests check the volume-header
boundaries and complete compressed sizes, observe both input volumes being
opened during extraction, and require extraction to fail when a continuation
volume is unavailable. Two linked aliases reuse the first split payload and
are not counted as additional physical splits.

## Fetch and run

Requires Python 3.11+, Rust, and a native linker. From the repository root:

```sh
python3 scripts/real-installers.py fetch
UNSHIELD_REQUIRE_REAL_INSTALLERS=asus-soundmax-4570,asus-realtek-lan-105,kodensha-jbeijing7-124,sony-sfcardviewer-264,epson-twain-571a \
  cargo test --locked --test real_installers -- --nocapture
python3 -m unittest discover -s tests -p 'test_*.py'
```

On PowerShell, set `$env:UNSHIELD_REQUIRE_REAL_INSTALLERS` to the comma-separated
IDs before running Cargo. The environment variable makes missing required inputs
fail. Without it, the Rust harness reports missing sample directories as skips.
An existing but incomplete or corrupted sample directory fails verification.

Inventories pin both installer and CAB/HDR SHA-256 values. `path` names a local input;
optional `archive_path` selects its location inside the ZIP. Only listed members
are unpacked, and their hashes are checked before replacement. Preserve all
listed numbered volumes even when one is empty. `engine32.cab` in the SoundMAX
package is Microsoft CAB, not InstallShield CAB, and is outside this corpus.

For `preparation.kind = embedded`, `offset` and `size` select verbatim CAB/HDR
byte ranges within the hash-pinned installer. Each range is checked against the
installer size and its own SHA-256 before replacing an input. The JBeijing and Sony
launchers' member headers independently state those lengths. This preparation
only reads bytes; it never runs an installer or invokes its extraction switches.
Downloaded executables and extracted payloads are never launched by the harness.

## Independent expected results

Build the original C implementation separately. This repository's `unshield_c`
links to Rust and cannot serve as an independent oracle. On Linux with CMake,
a C compiler, and zlib development files installed:

```sh
sh scripts/fetch-upstream.sh
cmake -S upstream/unshield -B build-reference \
  -DBUILD_TESTING=OFF -DBUILD_STATIC=ON -DUSE_OUR_OWN_MD5=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-reference --target libunshield
cc -std=c11 -Wall -Wextra -Werror -I upstream/unshield/lib \
  tests/reference_members.c build-reference/lib/libunshield.a \
  build-reference/lib/md5/CMakeFiles/md5.dir/md5c.c.o \
  -lz -o build-reference/reference-members
python3 scripts/real-installers.py reference \
  --extractor build-reference/reference-members
```

The MD5 object must be supplied when manually linking the upstream static
archive. Expected JSON records are pinned to upstream revision
`cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db`. Ubuntu CI rebuilds that source and
compares its outputs without rewriting expectations. The source revision check
does not itself prove which library a separately supplied executable links to;
use the build commands above.

For a new sample, first add a `candidate` inventory entry with known input
identities, independently identified version, and valid-member count. Fetch and
record only that explicitly named candidate:

```sh
python3 scripts/real-installers.py fetch SAMPLE_ID
python3 scripts/real-installers.py reference SAMPLE_ID \
  --extractor build-reference/reference-members --record-expected
```

Inspect the result, promote to `validated`, and run the Rust and C comparisons.
Do not generate expected hashes using a Rust-linked executable. `check-c`
rejects `--record-expected` to prevent accidental replacement of the oracle.

The extractor writes `<member-index>.bin` into a fresh temporary directory.
This preserves separate checks for duplicate filenames and avoids using archived
paths as filesystem destinations. Every valid member's original name bytes,
directory index, size, and SHA-256 are compared, alongside directory/component/
group metadata and total record counts. Invalid records are checked for index
and validity only: their placeholder names are not real filename evidence.

## C API validation

After fetching all validated samples:

```sh
cmake -S . -B build -DTEST_UPSTREAM_CLI=ON -DTEST_REAL_INSTALLERS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake -S . -B build-static -DBUILD_STATIC=ON -DBUILD_CLI=OFF \
  -DTEST_REAL_INSTALLERS=ON
cmake --build build-static --config Release
ctest --test-dir build-static -C Release --output-on-failure
cmake --install build --config Release --prefix "$PWD/install"
cmake -S tests/installed -B build-consumer -DCMAKE_PREFIX_PATH="$PWD/install" \
  -DTEST_REAL_INSTALLERS=ON
cmake --build build-consumer --config Release
ctest --test-dir build-consumer -C Release --output-on-failure
```

These C tests require all validated samples and fail when inputs are missing.
Both native I/O and custom file/directory callbacks extract every valid member.
Callback tests also require actual read/write/directory activity and balanced
resource closes. CI repeats shared, static, and installed-library checks on
Ubuntu, Windows, and macOS; Ubuntu also tests a relocated static pkg-config
consumer. CI artifacts retain Rust comparisons, the independent reference log,
and CTest logs.

See [measured coverage and limitations](../reports/real-installers.md) and
[task ownership](../PROJECT_STATUS_AND_TASKS.md). Fixed-input comparisons are
part of compatibility testing; differential fuzzing remains deferred.
