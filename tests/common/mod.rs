#![allow(dead_code)]
use flate2::{write::DeflateEncoder, Compression};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
pub fn u16at(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn u32at(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn u64at(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes());
}
pub struct Fixture {
    pub header: Vec<u8>,
    pub cabinet: Vec<u8>,
    pub payload: Vec<u8>,
    pub version: u32,
}
pub fn fixture(version: u32, flags: u16) -> Fixture {
    let payload = b"This is an InstallShield CAB fixture made for the Rust port.\n".repeat(3000);
    let stored = if flags & 4 != 0 {
        let mut result = Vec::new();
        for part in payload.chunks(64 * 1024) {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(part).unwrap();
            let compressed = encoder.finish().unwrap();
            result.extend_from_slice(&(compressed.len() as u16).to_le_bytes());
            result.extend_from_slice(&compressed);
        }
        result
    } else {
        payload.clone()
    };
    let mut stored = stored;
    if flags & 2 != 0 {
        for (i, b) in stored.iter_mut().enumerate() {
            *b = b.wrapping_add((i % 0x47) as u8).rotate_left(2) ^ 0xd5;
        }
    }
    let mut h = vec![0; 0xa00];
    let base = 0x100;
    let table = 0x500;
    let record = 0x540;
    u32at(&mut h, 0, 0x28635349);
    u32at(
        &mut h,
        4,
        if version == 0 {
            0x01000004
        } else if version == 5 {
            0x01005000
        } else {
            0x02000000 | (version * 100)
        },
    );
    u32at(&mut h, 12, base as u32);
    u32at(&mut h, 16, 0x400);
    u32at(&mut h, base + 0xc, (table - base) as u32);
    u32at(&mut h, base + 0x14, 0x500);
    u32at(&mut h, base + 0x18, 0x500);
    u32at(&mut h, base + 0x1c, 1);
    u32at(&mut h, base + 0x28, 1);
    u32at(&mut h, base + 0x2c, (record - table) as u32);
    u32at(&mut h, table, 0x100);
    u32at(&mut h, table + 4, (record - table) as u32);
    let set_string = |h: &mut [u8], p: usize, s: &str| {
        if version >= 17 {
            for (i, u) in s.encode_utf16().chain([0]).enumerate() {
                u16at(h, p + i * 2, u);
            }
        } else {
            h[p..p + s.len()].copy_from_slice(s.as_bytes());
            h[p + s.len()] = 0;
        }
    };
    set_string(&mut h, table + 0x100, "files");
    set_string(
        &mut h,
        table + 0x140,
        if version >= 17 {
            "hello-世界.txt"
        } else {
            "hello.txt"
        },
    );
    if version <= 5 {
        u32at(&mut h, record, 0x140);
        u16at(&mut h, record + 8, flags);
        u32at(&mut h, record + 10, payload.len() as u32);
        u32at(&mut h, record + 14, stored.len() as u32);
        u32at(&mut h, record + 38, 0x100);
        if version == 5 {
            h[record + 42..record + 58].copy_from_slice(&md5::compute(&payload).0);
        }
    } else {
        u16at(&mut h, record, flags);
        u64at(&mut h, record + 2, payload.len() as u64);
        u64at(&mut h, record + 10, stored.len() as u64);
        u64at(&mut h, record + 18, 0x100);
        h[record + 26..record + 42].copy_from_slice(&md5::compute(&payload).0);
        u32at(&mut h, record + 0x3a, 0x140);
        u16at(&mut h, record + 0x55, 1);
    }
    // One group and one component with a group reference.
    u32at(&mut h, base + 0x3e, 0x280);
    u32at(&mut h, base + 0x280 + 4, 0x2a0);
    u32at(&mut h, base + 0x2a0, 0x350);
    let range = base + 0x2a0 + if version <= 5 { 0x4c } else { 0x16 };
    u32at(&mut h, range, 0);
    u32at(&mut h, range + 4, 0);
    set_string(&mut h, base + 0x350, "Main");
    u32at(&mut h, base + 0x15a, 0x360);
    u32at(&mut h, base + 0x360 + 4, 0x700);
    u32at(&mut h, base + 0x700, 0x380);
    set_string(&mut h, base + 0x380, "Application");
    let g = base + 0x700 + if version <= 5 { 0x70 } else { 0x6f };
    u16at(&mut h, g, 1);
    u32at(&mut h, g + 2, 0x790);
    u32at(&mut h, base + 0x790, 0x350);
    let mut cabinet = vec![0; 0x100];
    cabinet[..20].copy_from_slice(&h[..20]);
    u32at(&mut cabinet, 16, 0);
    if version <= 5 {
        u32at(&mut cabinet, 20, 0x100);
        u32at(&mut cabinet, 36, 0x100);
        u32at(&mut cabinet, 40, payload.len() as u32);
        u32at(&mut cabinet, 44, stored.len() as u32);
        u32at(&mut cabinet, 48, 0x100);
        u32at(&mut cabinet, 52, payload.len() as u32);
        u32at(&mut cabinet, 56, stored.len() as u32);
    } else {
        u64at(&mut cabinet, 20, 0x100);
        u64at(&mut cabinet, 36, 0x100);
        u64at(&mut cabinet, 44, payload.len() as u64);
        u64at(&mut cabinet, 52, stored.len() as u64);
        u64at(&mut cabinet, 60, 0x100);
        u64at(&mut cabinet, 68, payload.len() as u64);
        u64at(&mut cabinet, 76, stored.len() as u64);
    }
    cabinet.extend_from_slice(&stored);
    Fixture {
        header: h,
        cabinet,
        payload,
        version,
    }
}
static NEXT: AtomicUsize = AtomicUsize::new(0);
pub fn embedded(f: &Fixture) -> Vec<u8> {
    let mut result = f.header.clone();
    let offset = result.len() as u64;
    result[20..84].copy_from_slice(&f.cabinet[20..84]);
    u64at(&mut result, 0x540 + 18, offset);
    u64at(&mut result, 20, offset);
    u64at(&mut result, 36, offset);
    u64at(&mut result, 60, offset);
    result.extend_from_slice(&f.cabinet[0x100..]);
    result
}
pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "unshield-rs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Fixture {
    pub fn write(&self, dir: &TempDir) -> PathBuf {
        fs::write(dir.0.join("data1.hdr"), &self.header).unwrap();
        fs::write(dir.0.join("data1.cab"), &self.cabinet).unwrap();
        dir.0.join("data1.cab")
    }
}
