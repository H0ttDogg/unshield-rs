mod common;
use common::*;
use std::{ffi::CString, fs, path::Path, process::Command};
use unshield::{ffi::*, Archive, Compression, Metadata};

#[test]
fn metadata_extents_and_descriptor_offsets_are_checked() {
    let f = fixture(6, 4);
    for (field, value) in [
        (16, 1),
        (0x114, 4),
        (0x384, 0xffff_fefe),
        (0x464, 0xffff_fefe),
        (0x388, 0xffff_fefe),
        (0x871, 0xffff_fefe),
    ] {
        let mut header = f.header.clone();
        u32at(&mut header, field, value);
        assert!(
            Metadata::parse(&header, None).is_err(),
            "accepted field {field:#x}"
        );
    }
    let mut header = f.header;
    header.resize(0xb00, 0);
    u32at(&mut header, 0x540 + 0x3a, 0x550);
    header[0xa50..0xa55].copy_from_slice(b"oops\0");
    assert!(
        Metadata::parse(&header, None).is_err(),
        "name points beyond declared metadata"
    );
}

#[test]
fn oversized_and_repeated_names_have_allocation_limits() {
    let mut header = fixture(6, 0).header;
    header.resize(0xa00 + 65540, b'a');
    *header.last_mut().unwrap() = 0;
    let size = (header.len() - 0x500) as u32;
    u32at(&mut header, 0x114, size);
    u32at(&mut header, 0x540 + 0x3a, 0x500);
    assert!(Metadata::parse(&header, None)
        .unwrap_err()
        .to_string()
        .contains("excessive string"));

    let dirs = 5000;
    let offset = dirs * 4;
    let mut header = fixture(6, 0).header;
    header.resize(0x500 + offset + 8193, 0);
    u32at(&mut header, 0x11c, dirs as u32);
    u32at(&mut header, 0x128, 0);
    let size = (header.len() - 0x500) as u32;
    u32at(&mut header, 0x114, size);
    for i in 0..dirs {
        u32at(&mut header, 0x500 + i * 4, offset as u32);
    }
    header[0x500 + offset..0x500 + offset + 8192].fill(b'a');
    assert!(Metadata::parse(&header, None)
        .unwrap_err()
        .to_string()
        .contains("decoded metadata exceeds"));
}

#[test]
fn malformed_member_does_not_truncate_output_before_opening_input() {
    let dir = TempDir::new();
    let mut f = fixture(6, 0);
    f.cabinet.pop();
    let archive = Archive::open(f.write(&dir)).unwrap();
    let output = dir.0.join("existing.txt");
    fs::write(&output, b"keep me").unwrap();
    for index in [usize::MAX, 0] {
        assert!(archive
            .save(index, Some(&output), Compression::New)
            .is_err());
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
    }
}

#[test]
fn empty_legacy_member_at_end_of_cabinet_needs_no_external_file() {
    let dir = TempDir::new();
    let mut f = fixture(5, 0);
    u32at(&mut f.header, 0x540 + 10, 0);
    u32at(&mut f.header, 0x540 + 14, 0);
    f.cabinet.truncate(0x100);
    let archive = Archive::open(f.write(&dir)).unwrap();
    assert!(archive.extract(0, Compression::Old).unwrap().is_empty());
}

#[test]
fn trailing_compressed_chunk_bytes_are_rejected() {
    let dir = TempDir::new();
    let mut f = fixture(6, 4);
    let length = u16::from_le_bytes(f.cabinet[0x100..0x102].try_into().unwrap());
    f.cabinet.insert(0x102 + length as usize, 0x55);
    u16at(&mut f.cabinet, 0x100, length + 1);
    let stored = f.cabinet.len() - 0x100;
    u64at(&mut f.header, 0x540 + 10, stored as u64);
    let archive = Archive::open(f.write(&dir)).unwrap();
    assert!(archive
        .extract(0, Compression::New)
        .unwrap_err()
        .to_string()
        .contains("trailing data"));
}

#[test]
fn c_deobfuscation_allows_seed_overlapping_buffer() {
    let mut actual = [0x1234_5678_u32, 0x8765_4321];
    let mut expected = actual
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect::<Vec<_>>();
    let mut seed = actual[0];
    unshield::deobfuscate(&mut expected, &mut seed);
    expected[..4].copy_from_slice(&seed.to_ne_bytes());
    let pointer = actual.as_mut_ptr();
    unsafe { unshield_deobfuscate(pointer.cast(), 8, pointer) };
    let bytes = actual
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect::<Vec<_>>();
    assert_eq!(bytes, expected);
}

#[test]
fn c_mutable_group_records_are_observed_by_accessors() {
    let dir = TempDir::new();
    let path = fixture(6, 0).write(&dir);
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let replacement = CString::new("Renamed").unwrap();
    unsafe {
        let handle = unshield_open(path.as_ptr());
        assert!(!handle.is_null());
        let group = unshield_file_group_get(handle, 0);
        (*group).name = replacement.as_ptr();
        (*group).first_file = -1;
        assert_eq!(unshield_file_group_name(handle, 0), replacement.as_ptr());
        assert_eq!(
            unshield_file_group_find(handle, replacement.as_ptr()),
            group
        );
        assert!(unshield_file_group_find(handle, c"Main".as_ptr()).is_null());
        assert_eq!((*unshield_file_group_get(handle, 0)).first_file, -1);
        assert!(unshield_file_save(handle, 0, std::ptr::null()));
        unshield_close(handle);
    }
}

fn cli_extract(cab: &Path, out: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_unshield-rs"))
        .args(["-j", "-d"])
        .arg(out)
        .arg("x")
        .arg(cab)
        .output()
        .unwrap()
}

#[test]
fn cli_failed_extraction_preserves_existing_files_and_cleans_temporary() {
    let dir = TempDir::new();
    let out = TempDir::new();
    let mut f = fixture(6, 4);
    f.header[0x540 + 26] ^= 1;
    let cab = f.write(&dir);
    let dest = out.0.join("hello.txt");
    fs::write(&dest, b"previous contents").unwrap();
    let result = cli_extract(&cab, &out.0);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("checksum"));
    assert_eq!(fs::read(&dest).unwrap(), b"previous contents");
    assert_eq!(fs::read_dir(&out.0).unwrap().count(), 1);
    fs::remove_file(&dest).unwrap();
    assert!(!cli_extract(&cab, &out.0).status.success());
    assert_eq!(fs::read_dir(&out.0).unwrap().count(), 0);
}

#[test]
fn cli_success_replaces_existing_hardlink_without_modifying_its_target() {
    let dir = TempDir::new();
    let out = TempDir::new();
    let f = fixture(6, 4);
    let cab = f.write(&dir);
    let external = dir.0.join("important.txt");
    fs::write(&external, b"keep me").unwrap();
    fs::hard_link(&external, out.0.join("hello.txt")).unwrap();
    let result = cli_extract(&cab, &out.0);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(&external).unwrap(), b"keep me");
    assert_eq!(fs::read(out.0.join("hello.txt")).unwrap(), f.payload);
    assert_eq!(fs::read_dir(&out.0).unwrap().count(), 1);
}

#[test]
fn cli_group_filter_checks_all_overlapping_groups() {
    let dir = TempDir::new();
    let out = TempDir::new();
    let mut f = fixture(6, 4);
    // Both groups contain member zero, and the requested one is second.
    u32at(&mut f.header, 0x388, 0x290);
    u32at(&mut f.header, 0x394, 0x2d0);
    u32at(&mut f.header, 0x3d0, 0x3a0);
    f.header[0x4a0..0x4aa].copy_from_slice(b"Secondary\0");
    u32at(&mut f.header, 0x890, 0x3a0);
    let cab = f.write(&dir);
    let result = Command::new(env!("CARGO_BIN_EXE_unshield-rs"))
        .args(["-g", "Secondary", "-c", "Application", "-d"])
        .arg(&out.0)
        .arg("x")
        .arg(cab)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(out.0.join("Secondary/files/hello.txt")).unwrap(),
        f.payload
    );
}

#[cfg(unix)]
#[test]
fn native_lookup_does_not_conflate_non_utf8_filenames() {
    use std::os::unix::ffi::OsStrExt;
    use unshield::io::{CabinetIo, NativeIo};
    let dir = TempDir::new();
    let created = fs::write(
        dir.0.join(std::ffi::OsStr::from_bytes(b"\xffDATA1.CAB")),
        b"wrong",
    );
    // macOS filesystems can reject non-UTF-8 names before lookup is possible.
    // Only that specific limitation skips this case; all other I/O errors fail.
    if created
        .as_ref()
        .is_err_and(|e| e.raw_os_error() == Some(libc::EILSEQ))
    {
        return;
    }
    created.unwrap();
    assert!(NativeIo
        .find(&dir.0.join(std::ffi::OsStr::from_bytes(b"\xfeDATA1.CAB")))
        .is_err());
    assert!(NativeIo
        .find(&dir.0.join(std::ffi::OsStr::from_bytes(b"\xffdata1.cab")))
        .is_ok());
}

#[cfg(unix)]
#[test]
fn cli_refuses_symlink_destinations() {
    let dir = TempDir::new();
    let out = TempDir::new();
    let f = fixture(6, 4);
    let cab = f.write(&dir);
    let external = dir.0.join("important.txt");
    fs::write(&external, b"keep me").unwrap();
    std::os::unix::fs::symlink(&external, out.0.join("hello.txt")).unwrap();
    assert!(!cli_extract(&cab, &out.0).status.success());
    assert_eq!(fs::read(&external).unwrap(), b"keep me");
}

#[cfg(windows)]
#[test]
fn windows_device_names_and_normalization_are_rejected() {
    for name in [
        "NUL",
        "aux.txt",
        "COM1",
        "LPT².txt",
        "CONIN$",
        ".. /escape",
        ".../escape",
        "folder./file",
        "file ",
        "file:stream",
        "file?",
        "a\u{1}b",
    ] {
        assert!(unshield::safe_relative(name).is_err(), "accepted {name:?}");
    }
    assert_eq!(
        unshield::safe_relative("folder\\normal.txt").unwrap(),
        Path::new("folder/normal.txt")
    );
}
