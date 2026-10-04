#![forbid(unsafe_code)]
use crate::error::{invalid, Error, Result};
use std::collections::HashSet;

pub(crate) const SIGNATURE: u32 = 0x2863_5349;
pub const FILE_SPLIT: u16 = 1;
pub const FILE_OBFUSCATED: u16 = 2;
pub const FILE_COMPRESSED: u16 = 4;
pub const FILE_INVALID: u16 = 8;

pub(crate) struct Bytes<'a>(pub &'a [u8]);
impl<'a> Bytes<'a> {
    pub fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8]> {
        self.0
            .get(
                offset
                    ..offset
                        .checked_add(len)
                        .ok_or_else(|| invalid("offset overflow"))?,
            )
            .ok_or_else(|| {
                invalid(format!(
                    "truncated metadata at {offset:#x}, length {len:#x}"
                ))
            })
    }
    pub fn u16(&self, p: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.slice(p, 2)?.try_into().unwrap()))
    }
    pub fn u32(&self, p: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.slice(p, 4)?.try_into().unwrap()))
    }
    pub fn u64(&self, p: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.slice(p, 8)?.try_into().unwrap()))
    }
    fn string(&self, p: usize, unicode: bool) -> Result<String> {
        let tail = self
            .0
            .get(p..)
            .ok_or_else(|| invalid("string offset outside header"))?;
        if unicode {
            let mut units = Vec::new();
            for pair in tail.as_chunks::<2>().0 {
                let unit = u16::from_le_bytes([pair[0], pair[1]]);
                if unit == 0 {
                    return String::from_utf16(&units)
                        .map_err(|_| invalid("invalid UTF-16 string"));
                }
                units.push(unit);
            }
        } else if let Some(end) = tail.iter().position(|&b| b == 0) {
            // C exposes these bytes verbatim. The FFI keeps the original bytes separately.
            return Ok(String::from_utf8_lossy(&tail[..end]).into_owned());
        }
        Err(invalid("unterminated string"))
    }
    fn raw_string(&self, p: usize, unicode: bool) -> Result<Vec<u8>> {
        if unicode {
            return Ok(self.string(p, true)?.into_bytes());
        }
        let tail = self
            .0
            .get(p..)
            .ok_or_else(|| invalid("string offset outside header"))?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| invalid("unterminated string"))?;
        Ok(tail[..end].to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    /// Original narrow name bytes, or UTF-8 for Unicode cabinets.
    pub name_bytes: Vec<u8>,
    pub name_offset: u32,
    pub directory_index: usize,
    pub flags: u16,
    pub expanded_size: u64,
    pub compressed_size: u64,
    pub data_offset: u64,
    pub md5: [u8; 16],
    pub volume: u16,
    pub link_previous: u32,
    pub link_next: u32,
    pub link_flags: u8,
}
impl FileEntry {
    pub fn is_valid(&self) -> bool {
        self.flags & FILE_INVALID == 0 && self.name_offset != 0 && self.data_offset != 0
    }
}
#[derive(Debug, Clone)]
pub struct FileGroup {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub first_file: i32,
    pub last_file: i32,
}
#[derive(Debug, Clone)]
pub struct Component {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub file_groups: Vec<String>,
    pub group_bytes: Vec<Vec<u8>>,
}
#[derive(Debug, Clone)]
pub struct Metadata {
    pub major_version: u32,
    pub directories: Vec<String>,
    pub directory_bytes: Vec<Vec<u8>>,
    pub files: Vec<FileEntry>,
    pub file_groups: Vec<FileGroup>,
    pub components: Vec<Component>,
}

pub(crate) fn common(data: &[u8], force: Option<u32>) -> Result<(u32, usize, usize)> {
    let b = Bytes(data);
    let sig = b.u32(0)?;
    if sig != SIGNATURE {
        return Err(invalid(if sig == 0x4643_534d {
            "Microsoft CAB is a different format"
        } else {
            "bad signature"
        }));
    }
    b.slice(0, 20)?;
    let version = b.u32(4)?;
    let major = match force {
        Some(v) => v,
        None => match version >> 24 {
            1 => (version >> 12) & 15,
            2 | 4 => (version & 0xffff) / 100,
            _ => return Err(Error::UnsupportedVersion(version)),
        },
    };
    if major != 0 && major < 5 {
        return Err(Error::UnsupportedVersion(major));
    }
    let base = b.u32(12)? as usize;
    let size = b.u32(16)? as usize;
    if size == 0 {
        return Err(invalid("no CAB descriptor"));
    }
    Ok((major, base, size))
}

impl Metadata {
    /// Parse header metadata without accessing cabinet payloads.
    pub fn parse(data: &[u8], force_version: Option<u32>) -> Result<Self> {
        let (major, base, descriptor_size) = common(data, force_version)?;
        let b = Bytes(data);
        b.slice(base, descriptor_size)?;
        b.slice(base, 0x276)?;
        let relative = |o: u32| {
            base.checked_add(o as usize)
                .ok_or_else(|| invalid("offset overflow"))
        };
        let table = relative(b.u32(base + 0x0c)?)?;
        let table_size = b.u32(base + 0x14)? as usize;
        b.slice(table, table_size)?;
        let dirs = b.u32(base + 0x1c)? as usize;
        let count = b.u32(base + 0x28)? as usize;
        let count_all = dirs
            .checked_add(count)
            .ok_or_else(|| invalid("entry count overflow"))?;
        if count_all > 1_000_000 {
            return Err(invalid("too many directory/file entries"));
        }
        b.slice(
            table,
            count_all
                .checked_mul(4)
                .ok_or_else(|| invalid("table size overflow"))?,
        )?;
        let unicode = major >= 17;
        let name_at = |p| b.string(p, unicode);
        let raw_at = |p| b.raw_string(p, unicode);
        let table_relative = |o: u32| {
            table
                .checked_add(o as usize)
                .ok_or_else(|| invalid("table offset overflow"))
        };
        let mut directories = Vec::with_capacity(dirs);
        let mut directory_bytes = Vec::with_capacity(dirs);
        for i in 0..dirs {
            let p = table_relative(b.u32(table + i * 4)?)?;
            directories.push(name_at(p)?);
            directory_bytes.push(raw_at(p)?);
        }
        let records = table_relative(b.u32(base + 0x2c)?)?;
        let mut files = Vec::with_capacity(count);
        for i in 0..count {
            let (
                p,
                name,
                directory,
                flags,
                expanded,
                compressed,
                offset,
                digest,
                volume,
                previous,
                next,
                links,
            ) = if major <= 5 {
                let p = table_relative(b.u32(table + (dirs + i) * 4)?)?;
                b.slice(p, if major == 5 { 0x3a } else { 0x2a })?;
                (
                    p,
                    b.u32(p)?,
                    b.u16(p + 4)? as usize,
                    b.u16(p + 8)?,
                    b.u32(p + 10)? as u64,
                    b.u32(p + 14)? as u64,
                    b.u32(p + 38)? as u64,
                    if major == 5 {
                        b.slice(p + 42, 16)?.try_into().unwrap()
                    } else {
                        [0; 16]
                    },
                    1,
                    0,
                    0,
                    0,
                )
            } else {
                let p = records
                    .checked_add(i * 0x57)
                    .ok_or_else(|| invalid("record offset overflow"))?;
                b.slice(p, 0x57)?;
                (
                    p,
                    b.u32(p + 0x3a)?,
                    b.u16(p + 0x3e)? as usize,
                    b.u16(p)?,
                    b.u64(p + 2)?,
                    b.u64(p + 10)?,
                    b.u64(p + 18)?,
                    b.slice(p + 26, 16)?.try_into().unwrap(),
                    b.u16(p + 0x55)?,
                    b.u32(p + 0x4c)?,
                    b.u32(p + 0x50)?,
                    b.slice(p + 0x54, 1)?[0],
                )
            };
            if flags & FILE_INVALID == 0 && name != 0 && directory >= dirs {
                return Err(invalid(format!("bad directory index at {p:#x}")));
            }
            let name_offset = name;
            let (name, name_bytes) = if name == 0 {
                (String::new(), Vec::new())
            } else {
                let p = table_relative(name)?;
                (name_at(p)?, raw_at(p)?)
            };
            files.push(FileEntry {
                name,
                name_bytes,
                name_offset,
                directory_index: directory,
                flags,
                expanded_size: expanded,
                compressed_size: compressed,
                data_offset: offset,
                md5: digest,
                volume,
                link_previous: previous,
                link_next: next,
                link_flags: links,
            });
        }
        // Each hash bucket contains a linked list. Detect cycles before following untrusted offsets.
        let lists = |start: usize| -> Result<Vec<usize>> {
            let mut result = Vec::new();
            let mut visited = HashSet::new();
            for i in 0..71 {
                let mut offset = b.u32(base + start + i * 4)?;
                while offset != 0 {
                    if !visited.insert(offset) {
                        return Err(invalid("cyclic or duplicate descriptor list"));
                    }
                    if visited.len() > 1_000_000 {
                        return Err(invalid("too many descriptors"));
                    }
                    let p = relative(offset)?;
                    result.push(relative(b.u32(p + 4)?)?);
                    offset = b.u32(p + 8)?;
                }
            }
            Ok(result)
        };
        let mut file_groups = Vec::new();
        for p in lists(0x3e)? {
            let name_p = relative(b.u32(p)?)?;
            let range = p + if major <= 5 { 0x4c } else { 0x16 };
            let first = b.u32(range)? as i32;
            let last = b.u32(range + 4)? as i32;
            if first < -1 || last < -1 || (first >= 0 && (last < first || last as usize >= count)) {
                return Err(invalid("bad file group range"));
            }
            file_groups.push(FileGroup {
                name: name_at(name_p)?,
                name_bytes: raw_at(name_p)?,
                first_file: first,
                last_file: last,
            });
        }
        let mut components = Vec::new();
        for p in lists(0x15a)? {
            let name_p = relative(b.u32(p)?)?;
            let groups_p = p + if major <= 5 { 0x70 } else { 0x6f };
            let group_count = b.u16(groups_p)? as usize;
            if group_count > 71 {
                return Err(invalid("too many groups in component"));
            }
            let group_table = relative(b.u32(groups_p + 2)?)?;
            let mut groups = Vec::new();
            let mut group_bytes = Vec::new();
            for i in 0..group_count {
                let p = relative(b.u32(group_table + i * 4)?)?;
                groups.push(name_at(p)?);
                group_bytes.push(raw_at(p)?);
            }
            components.push(Component {
                name: name_at(name_p)?,
                name_bytes: raw_at(name_p)?,
                file_groups: groups,
                group_bytes,
            });
        }
        Ok(Self {
            major_version: major,
            directories,
            directory_bytes,
            files,
            file_groups,
            components,
        })
    }
}
