#!/usr/bin/env python3
"""Fetch CAB sets, verify the independent C reference, or check C ABI extraction."""
import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = "cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(base, name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise ValueError(f"unsafe inventory path: {name!r}")
    return base.joinpath(*path.parts)


def inventories():
    samples = []
    for family in ("v6-16", "v17-plus"):
        inventory = json.loads((ROOT / "corpus" / f"{family}.json").read_text(encoding="utf-8"))
        if inventory["schema_version"] != 1 or inventory["family"] != family:
            raise ValueError(f"unsupported inventory: {family}")
        if not inventory["samples"]:
            print(f"SKIP {family}: no samples recorded", flush=True)
        samples.extend(inventory["samples"])
    ids = [s["id"] for s in samples]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate sample IDs")
    return samples


def verify(path, expected):
    actual = digest(path)
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {path}: expected {expected}, got {actual}")


def sample_dir(sample):
    sid = sample["id"]
    if not sid or not all(c.isascii() and (c.isalnum() or c == "-") for c in sid):
        raise ValueError(f"invalid sample ID: {sid!r}")
    return ROOT / "test-data" / "real-installers" / sid


def verify_inputs(sample, directory):
    for item in [sample["installer"], *sample["inputs"]]:
        verify(relative(directory, item["path"]), item["sha256"])
    header = relative(directory, sample["version_file"]).read_bytes()[:8]
    raw = int.from_bytes(header[4:8], "little")
    if header[:4] != b"ISc(" or raw != sample["raw_version"]:
        raise ValueError("CAB signature/version does not match inventory")
    family = raw >> 24
    major = (raw >> 12) & 15 if family == 1 else (raw & 65535) // 100
    if family not in (1, 2, 4) or major != sample["major_version"]:
        raise ValueError("independent format-major identification failed")


def fetch(sample):
    directory = sample_dir(sample)
    directory.mkdir(parents=True, exist_ok=True)
    installer = relative(directory, sample["installer"]["path"])
    if not installer.exists():
        installer.parent.mkdir(parents=True, exist_ok=True)
        # Download and verify before replacing any local file.
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            download = Path(temporary) / "download"
            print(f"FETCH {sample['id']}: {sample['source_url']}", flush=True)
            with urllib.request.urlopen(sample["source_url"], timeout=120) as response:
                with download.open("wb") as output:
                    while block := response.read(1024 * 1024):
                        output.write(block)
            verify(download, sample["installer"]["sha256"])
            download.replace(installer)
    verify(installer, sample["installer"]["sha256"])
    kind = sample["preparation"]["kind"]
    if kind not in ("zip", "embedded"):
        raise ValueError(f"unsupported preparation kind: {kind}")
    # Embedded inputs are verbatim byte ranges in a hash-pinned launcher.
    # Never execute a downloaded installer, including its unpacking switches.
    with (zipfile.ZipFile(installer) if kind == "zip" else nullcontext()) as archive:
        for item in sample["inputs"]:
            output = relative(directory, item["path"])
            if output.exists():
                verify(output, item["sha256"])
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=directory) as temporary:
                unpacked = Path(temporary) / "member"
                if kind == "embedded":
                    offset, size = item["offset"], item["size"]
                    if (type(offset) is not int or type(size) is not int or
                            offset < 0 or size <= 0 or offset + size > installer.stat().st_size):
                        raise ValueError(f"invalid embedded input range: {item['path']}")
                    source_file = installer.open("rb")
                else:
                    source_file = archive.open(item.get("archive_path", item["path"]))
                    size = None
                with source_file as source, unpacked.open("wb") as target:
                    if kind == "embedded":
                        source.seek(offset)
                    remaining = size
                    while remaining is None or remaining:
                        block = source.read(1024 * 1024 if remaining is None else min(remaining, 1024 * 1024))
                        if not block:
                            if remaining:
                                raise ValueError(f"truncated embedded input: {item['path']}")
                            break
                        target.write(block)
                        if remaining is not None:
                            remaining -= len(block)
                verify(unpacked, item["sha256"])
                unpacked.replace(output)
    verify_inputs(sample, directory)
    print(f"READY {sample['id']}: format {sample['major_version']}, all input identities verified", flush=True)


def comparable(metadata):
    # Invalid records have no meaningful filename/size/directory. Preserve their
    # indices and validity, just as the Rust regression harness does.
    return {**metadata, "files": [m if m["valid"] else
            {"index": m["index"], "valid": False} for m in metadata["files"]]}


def compare(sample, extractor, record=False, io_mode="native", independent=True):
    if independent:
        revision = subprocess.check_output(
            ["git", "-C", str(ROOT / "upstream/unshield"), "rev-parse", "HEAD"], text=True
        ).strip()
        if revision != REFERENCE:
            raise ValueError(f"reference source must be pinned to {REFERENCE}, got {revision}")
    directory = sample_dir(sample)
    verify_inputs(sample, directory)
    with tempfile.TemporaryDirectory(prefix="reference-", dir=directory) as temporary:
        command = [str(extractor.resolve()), str(relative(directory, sample["entry_cab"])),
                   temporary, sample["compression"], io_mode]
        label = "REFERENCE" if independent else f"C-ABI/{io_mode}"
        print(label, command, flush=True)
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr}")
        metadata = json.loads(result.stdout)
        metadata.update(sample_id=sample["id"], reference_revision=REFERENCE)
        for member in metadata["files"]:
            index = member["index"]
            if member["valid"]:
                output = Path(temporary) / f"{index}.bin"
                if output.stat().st_size != member["expanded_size"]:
                    raise ValueError(f"reference size mismatch for member {index}")
                member["sha256"] = digest(output)
            else:
                member["sha256"] = None
        if sum(m["valid"] for m in metadata["files"]) != sample["expected_valid_members"]:
            raise ValueError("valid-member count differs from inventory")
        expected = relative(ROOT, sample["expected"])
        if record:
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            print(f"RECORDED {expected.relative_to(ROOT)}", flush=True)
        elif comparable(json.loads(expected.read_text(encoding="utf-8"))) != comparable(metadata):
            raise ValueError(f"{label} output differs from {expected}")
        else:
            print(f"MATCH {label} {sample['id']}: {sample['expected_valid_members']} valid members, metadata and every SHA-256", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "reference", "check-c"))
    parser.add_argument("ids", nargs="*", help="default: all validated samples")
    parser.add_argument("--extractor", type=Path, help="member extractor linked to upstream C (reference) or Rust (check-c)")
    parser.add_argument("--io", choices=("native", "callbacks"), default="native")
    parser.add_argument("--record-expected", action="store_true", help="explicitly replace expected metadata/hashes")
    args = parser.parse_args()
    if args.action != "fetch" and not args.extractor:
        parser.error(f"{args.action} requires --extractor")
    if args.record_expected and (args.action != "reference" or not args.ids):
        parser.error("--record-expected requires reference and explicit sample IDs")
    samples = inventories()
    unknown = set(args.ids) - {s["id"] for s in samples}
    if unknown:
        parser.error(f"unknown samples: {sorted(unknown)}")
    selected = 0
    for sample in samples:
        if args.ids and sample["id"] not in args.ids:
            continue
        if sample["status"] != "validated" and not (args.ids and
                (args.action == "fetch" or args.record_expected)):
            print(f"SKIP {sample['id']}: candidate has no verified reference output", flush=True)
            continue
        selected += 1
        if args.action == "fetch":
            fetch(sample)
        else:
            compare(sample, args.extractor, args.record_expected, args.io,
                    independent=args.action == "reference")
    if selected == 0:
        parser.error("no eligible samples selected")


if __name__ == "__main__":
    main()
