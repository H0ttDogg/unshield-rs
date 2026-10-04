mod common;
use common::*;
use std::{
    ffi::{CStr, CString},
    fs, ptr,
};
use unshield::{ffi::*, Archive, Compression, Metadata};

#[test]
fn extract_version_families() {
    for version in [0, 5, 6, 7, 13, 17, 20] {
        for flags in [0, 2, 4, 6] {
            let f = fixture(version, flags);
            let dir = TempDir::new();
            let archive = Archive::open(f.write(&dir)).unwrap();
            assert_eq!(archive.metadata().major_version, version);
            assert_eq!(archive.extract(0, Compression::New).unwrap(), f.payload);
            assert_eq!(archive.metadata().components[0].file_groups, ["Main"]);
            assert_eq!(archive.metadata().file_groups[0].first_file, 0);
            if version >= 17 {
                assert_eq!(archive.files()[0].name, "hello-世界.txt");
            }
        }
    }
}
#[test]
fn raw_deobfuscates_without_decompressing() {
    let f = fixture(6, 6);
    let dir = TempDir::new();
    let archive = Archive::open(f.write(&dir)).unwrap();
    let mut expected = f.cabinet[0x100..].to_vec();
    unshield::deobfuscate(&mut expected, &mut 0);
    assert_eq!(archive.extract(0, Compression::Raw).unwrap(), expected);
}
#[test]
fn truncated_metadata_and_bad_offsets_return_errors() {
    let f = fixture(6, 4);
    for end in 0..f.header.len() {
        assert!(
            Metadata::parse(&f.header[..end], None).is_err(),
            "accepted truncation {end}"
        );
    }
    let mut h = f.header.clone();
    u32at(&mut h, 0x100 + 0xc, u32::MAX);
    assert!(Metadata::parse(&h, None).is_err());
    let mut h = f.header.clone();
    u32at(&mut h, 0x100 + 0x1c, u32::MAX);
    assert!(Metadata::parse(&h, None).is_err());
    let mut h = f.header.clone();
    u32at(&mut h, 0x100 + 0x280 + 8, 0x280);
    assert!(Metadata::parse(&h, None).is_err());
}
#[test]
fn damaged_payloads_and_checksums_fail() {
    let mut f = fixture(6, 4);
    f.header[0x540 + 26] ^= 1;
    let dir = TempDir::new();
    let a = Archive::open(f.write(&dir)).unwrap();
    assert!(matches!(
        a.extract(0, Compression::New),
        Err(unshield::Error::Checksum(0))
    ));
    let mut f = fixture(6, 4);
    f.cabinet[0x100..0x102].fill(0);
    let a = Archive::open(f.write(&dir)).unwrap();
    assert!(a.extract(0, Compression::New).is_err());
    let mut f = fixture(6, 4);
    f.cabinet.pop();
    let a = Archive::open(f.write(&dir)).unwrap();
    assert!(a.extract(0, Compression::New).is_err());
}
#[test]
fn link_cycles_are_rejected() {
    let mut f = fixture(6, 4);
    f.header[0x540 + 0x54] = 1;
    let dir = TempDir::new();
    let a = Archive::open(f.write(&dir)).unwrap();
    assert!(a
        .extract(0, Compression::New)
        .unwrap_err()
        .to_string()
        .contains("cyclic"));
}
#[test]
fn split_payload_including_chunk_prefix_across_volumes() {
    for version in [5, 6, 17] {
        let mut f = fixture(version, 6);
        let stored = f.cabinet[0x100..].to_vec();
        let cut = 1;
        let mut second = f.cabinet[..0x100].to_vec();
        second.extend_from_slice(&stored[cut..]);
        f.cabinet.truncate(0x100 + cut);
        if version <= 5 {
            u16at(&mut f.header, 0x540 + 8, 7);
            u32at(&mut f.cabinet, 56, cut as u32);
            u32at(&mut second, 56, (stored.len() - cut) as u32);
        } else {
            u16at(&mut f.header, 0x540, 7);
            u64at(&mut f.cabinet, 76, cut as u64);
            u64at(&mut second, 76, (stored.len() - cut) as u64);
        }
        let dir = TempDir::new();
        let path = f.write(&dir);
        fs::write(dir.0.join("DATA2.CAB"), second).unwrap();
        assert_eq!(
            Archive::open(path)
                .unwrap()
                .extract(0, Compression::New)
                .unwrap(),
            f.payload
        );
    }
}
#[test]
fn deobfuscation_seed_is_continuous_and_wraps() {
    let mut bytes = (0..200).map(|i| i as u8).collect::<Vec<_>>();
    let mut expected = bytes.clone();
    let mut seed = u32::MAX - 90;
    let mut other = seed;
    unshield::deobfuscate(&mut expected, &mut other);
    unshield::deobfuscate(&mut bytes[..77], &mut seed);
    unshield::deobfuscate(&mut bytes[77..], &mut seed);
    assert_eq!(bytes, expected);
    assert_eq!(seed, other);
}
#[test]
fn c_api_owns_names_and_structs_until_close() {
    let f = fixture(17, 4);
    let dir = TempDir::new();
    let path = f.write(&dir);
    let name = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    unsafe {
        unshield_set_log_level(0);
        let h = unshield_open(name.as_ptr());
        assert!(!h.is_null());
        assert_eq!(unshield_file_count(h), 1);
        assert_eq!(unshield_component_count(h), 1);
        assert_eq!(unshield_file_group_count(h), 1);
        assert_eq!(unshield_directory_count(h), 1);
        let saved_name = unshield_file_name(h, 0);
        assert_eq!(
            CStr::from_ptr(saved_name).to_str().unwrap(),
            "hello-世界.txt"
        );
        assert_eq!(unshield_file_directory(h, 0), 0);
        assert_eq!(unshield_file_size(h, 0), f.payload.len());
        assert!(unshield_is_unicode(h));
        let g = unshield_file_group_get(h, 0);
        assert_eq!((*g).first_file, 0);
        assert_eq!((*g).last_file, 0);
        let key = CString::new("Main").unwrap();
        assert_eq!(g, unshield_file_group_find(h, key.as_ptr()));
        assert!(unshield_file_save(h, 0, ptr::null()));
        assert_eq!(unshield_file_name(h, 0), saved_name);
        assert!(unshield_file_is_valid(h, 0));
        assert!(unshield_file_name(h, -1).is_null());
        assert_eq!(unshield_file_directory(h, -1), -1);
        assert!(!unshield_file_save(h, -1, ptr::null()));
        unshield_close(h);
        unshield_close(ptr::null_mut());
        assert!(unshield_open(ptr::null()).is_null());
    }
}

#[test]
fn embedded_header_and_case_insensitive_lookup() {
    let f = fixture(6, 4);
    let dir = TempDir::new();
    fs::write(dir.0.join("DATA1.CAB"), embedded(&f)).unwrap();
    let a = Archive::open(dir.0.join("data1.cab")).unwrap();
    assert_eq!(a.extract(0, Compression::New).unwrap(), f.payload);
}

#[test]
fn legacy_names_retain_original_bytes_for_c() {
    let mut f = fixture(5, 0);
    f.header[0x640] = 0xe9;
    let dir = TempDir::new();
    let filename = f.write(&dir);
    let a = Archive::open(&filename).unwrap();
    assert_eq!(a.files()[0].name_bytes[0], 0xe9);
    let name = CString::new(filename.to_string_lossy().as_bytes()).unwrap();
    unsafe {
        let h = unshield_open(name.as_ptr());
        assert!(!h.is_null());
        assert_eq!(CStr::from_ptr(unshield_file_name(h, 0)).to_bytes()[0], 0xe9);
        unshield_close(h);
    }
}

#[test]
fn previous_file_link_extracts_target_bytes() {
    let mut f = fixture(6, 6);
    u32at(&mut f.header, 0x128, 2);
    let record = f.header[0x540..0x597].to_vec();
    f.header[0x597..0x5ee].copy_from_slice(&record);
    u32at(&mut f.header, 0x597 + 0x3a, 0x180);
    f.header[0x680..0x68a].copy_from_slice(b"alias.txt\0");
    f.header[0x597 + 0x54] = 1;
    u32at(&mut f.header, 0x597 + 0x4c, 0);
    u32at(&mut f.header, 0x3b6 + 4, 1);
    let dir = TempDir::new();
    let a = Archive::open(f.write(&dir)).unwrap();
    assert_eq!(a.files()[1].name, "alias.txt");
    assert_eq!(a.extract(1, Compression::New).unwrap(), f.payload);
}

#[test]
fn empty_compressed_member_is_valid() {
    let mut f = fixture(6, 4);
    u64at(&mut f.header, 0x540 + 2, 0);
    u64at(&mut f.header, 0x540 + 10, 4);
    f.header[0x540 + 26..0x540 + 42].copy_from_slice(&md5::compute([]).0);
    f.cabinet.truncate(0x100);
    f.cabinet.extend_from_slice(&[2, 0, 3, 0]);
    let dir = TempDir::new();
    let a = Archive::open(f.write(&dir)).unwrap();
    assert!(a.extract(0, Compression::New).unwrap().is_empty());
}

#[test]
fn volume_and_member_offsets_above_four_gib_are_not_truncated() {
    use std::{
        io::{self, Read, Seek, SeekFrom},
        path::{Path, PathBuf},
        rc::Rc,
    };
    use unshield::io::{CabinetIo, ReadSeek};
    struct Sparse {
        prefix: Vec<u8>,
        payload: Vec<u8>,
        offset: u64,
        position: u64,
    }
    impl Read for Sparse {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let length = self.offset + self.payload.len() as u64;
            let n = b
                .len()
                .min(length.saturating_sub(self.position).min(usize::MAX as u64) as usize);
            for (i, byte) in b[..n].iter_mut().enumerate() {
                let p = self.position + i as u64;
                *byte = if p < self.prefix.len() as u64 {
                    self.prefix[p as usize]
                } else if p >= self.offset {
                    self.payload[(p - self.offset) as usize]
                } else {
                    0
                };
            }
            self.position += n as u64;
            Ok(n)
        }
    }
    impl Seek for Sparse {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.position = match p {
                SeekFrom::Start(n) => n,
                SeekFrom::End(n) => (self.offset + self.payload.len() as u64)
                    .checked_add_signed(n)
                    .unwrap(),
                SeekFrom::Current(n) => self.position.checked_add_signed(n).unwrap(),
            };
            Ok(self.position)
        }
    }
    struct Storage {
        header: Vec<u8>,
        prefix: Vec<u8>,
        payload: Vec<u8>,
        offset: u64,
    }
    impl CabinetIo for Storage {
        fn find(&self, path: &Path) -> io::Result<PathBuf> {
            Ok(path.to_owned())
        }
        fn create(&self, _: &Path) -> io::Result<Box<dyn io::Write>> {
            Ok(Box::new(io::sink()))
        }
        fn open(&self, path: &Path) -> io::Result<Box<dyn ReadSeek>> {
            if path.extension().is_some_and(|s| s == "hdr") {
                Ok(Box::new(io::Cursor::new(self.header.clone())))
            } else {
                Ok(Box::new(Sparse {
                    prefix: self.prefix.clone(),
                    payload: self.payload.clone(),
                    offset: self.offset,
                    position: 0,
                }))
            }
        }
    }
    for flags in [0, 1] {
        let mut f = fixture(6, flags);
        let offset = (1u64 << 32) + 0x100;
        u64at(&mut f.header, 0x540 + 18, offset);
        u64at(&mut f.cabinet, 36, offset);
        u64at(&mut f.cabinet, 60, offset);
        let expected = f.payload.clone();
        let io = Rc::new(Storage {
            header: f.header,
            prefix: f.cabinet[..0x100].to_vec(),
            payload: f.payload,
            offset,
        });
        let a = Archive::open_with("data1.cab", None, io).unwrap();
        assert_eq!(a.files()[0].data_offset, offset);
        assert_eq!(a.extract(0, Compression::New).unwrap(), expected);
    }
}
