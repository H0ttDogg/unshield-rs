#![forbid(unsafe_code)]
use crate::{
    error::{invalid, Error, Result},
    format::{self, Bytes, MAX_HEADER},
    io::{CabinetIo, NativeIo, ReadSeek},
    FileEntry, Metadata, FILE_COMPRESSED, FILE_OBFUSCATED, FILE_SPLIT,
};
use flate2::{Decompress, FlushDecompress, Status};
use std::{
    collections::HashSet,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

const BLOCK_SIZE: usize = 64 * 1024;
const MARKER: [u8; 4] = [0, 0, 255, 255];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    New,
    Old,
    Raw,
}

/// Deobfuscation state is continuous across read calls and cabinet volumes.
pub fn deobfuscate(buffer: &mut [u8], seed: &mut u32) {
    for byte in buffer {
        *byte = (*byte ^ 0xd5)
            .rotate_right(2)
            .wrapping_sub((*seed % 0x47) as u8);
        *seed = seed.wrapping_add(1);
    }
}

pub struct Archive {
    metadata: Metadata,
    pub(crate) io: Rc<dyn CabinetIo>,
    directory: PathBuf,
    prefix: std::ffi::OsString,
}
impl Archive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, None, Rc::new(NativeIo))
    }
    pub fn open_force_version(path: impl AsRef<Path>, version: u32) -> Result<Self> {
        Self::open_with(path, Some(version), Rc::new(NativeIo))
    }
    pub fn open_with(
        path: impl AsRef<Path>,
        force_version: Option<u32>,
        io: Rc<dyn CabinetIo>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let filename = path
            .file_name()
            .ok_or_else(|| invalid("missing cabinet filename"))?;
        // Preserve upstream's base-name convention: the first digit or dot starts the volume suffix.
        #[cfg(unix)]
        let prefix = {
            use std::os::unix::ffi::OsStrExt;
            let bytes = filename.as_bytes();
            let end = bytes
                .iter()
                .position(|c| *c == b'.' || c.is_ascii_digit())
                .unwrap_or(bytes.len());
            std::ffi::OsStr::from_bytes(&bytes[..end]).to_os_string()
        };
        #[cfg(windows)]
        let prefix = {
            let name = filename.to_string_lossy();
            let end = name
                .find(|c: char| c == '.' || c.is_ascii_digit())
                .unwrap_or(name.len());
            std::ffi::OsString::from(&name[..end])
        };
        let numbered = |suffix: &str| {
            let mut name = prefix.clone();
            name.push(suffix);
            directory.join(name)
        };
        let hdr = numbered("1.hdr");
        let cab = numbered("1.cab");
        let mut input = match io.find(&hdr).and_then(|path| io.open(&path)) {
            Ok(input) => input,
            Err(e) if e.kind() == io::ErrorKind::NotFound => io.open(&io.find(&cab)?)?,
            Err(e) => return Err(e.into()),
        };
        let mut common = [0u8; 20];
        input.read_exact(&mut common)?;
        let (_, base, size) = format::common(&common, force_version)?;
        let descriptor_end = base
            .checked_add(size)
            .ok_or_else(|| invalid("descriptor size overflow"))?;
        if size < 0x276 || descriptor_end > MAX_HEADER {
            return Err(invalid("invalid or excessive descriptor size"));
        }
        let mut data = vec![0u8; descriptor_end];
        input.seek(SeekFrom::Start(0))?;
        input.read_exact(&mut data)?;
        let b = Bytes(&data);
        let table_end = base
            .checked_add(b.u32(base + 0xc)? as usize)
            .and_then(|p| p.checked_add(b.u32(base + 0x14).ok()? as usize))
            .ok_or_else(|| invalid("file table size overflow"))?;
        if table_end > MAX_HEADER {
            return Err(invalid("metadata exceeds 64 MiB"));
        }
        if table_end > data.len() {
            let old = data.len();
            data.resize(table_end, 0);
            input.read_exact(&mut data[old..])?;
        }
        let metadata = Metadata::parse(&data, force_version)?;
        Ok(Self {
            metadata,
            io,
            directory,
            prefix,
        })
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn files(&self) -> &[FileEntry] {
        &self.metadata.files
    }
    pub fn file(&self, index: usize) -> Result<&FileEntry> {
        self.files().get(index).ok_or(Error::InvalidIndex(index))
    }
    fn volume_path(&self, volume: u16) -> Result<PathBuf> {
        let mut name = self.prefix.clone();
        name.push(format!("{volume}.cab"));
        Ok(self.io.find(&self.directory.join(name))?)
    }
    fn resolve_link(&self, mut index: usize) -> Result<usize> {
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(index) {
                return Err(invalid("cyclic previous-file link"));
            }
            let file = self.file(index)?;
            if !file.is_valid() {
                return Err(Error::InvalidFile(index));
            }
            if file.link_flags & 1 == 0 {
                return Ok(index);
            }
            index = file.link_previous as usize;
        }
    }
    /// Stream one member into a writer. New mode checks the embedded MD5 for v6+.
    /// On error the writer may contain a partial member, as with the C library.
    pub fn extract_to(
        &self,
        index: usize,
        writer: &mut dyn Write,
        mode: Compression,
    ) -> Result<()> {
        let index = self.resolve_link(index)?;
        let reader = Payload::new(self, index, mode)?;
        self.extract_payload(index, reader, writer, mode)
    }
    fn extract_payload(
        &self,
        index: usize,
        mut reader: Payload<'_>,
        writer: &mut dyn Write,
        mode: Compression,
    ) -> Result<()> {
        let file = self.file(index)?;
        if mode == Compression::Raw {
            io::copy(&mut reader, writer)?;
            return Ok(());
        }
        let mut digest = md5::Context::new();
        let mut written = 0u64;
        let mut emit = |bytes: &[u8]| -> Result<()> {
            written = written
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("expanded size overflow"))?;
            if written > file.expanded_size {
                return Err(invalid("decompressed data exceeds expanded size"));
            }
            writer.write_all(bytes)?;
            digest.consume(bytes);
            Ok(())
        };
        if file.flags & FILE_COMPRESSED == 0 {
            let mut buffer = [0u8; BLOCK_SIZE];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                emit(&buffer[..n])?;
            }
        } else if mode == Compression::New {
            while reader.remaining != 0 {
                let mut size = [0u8; 2];
                reader.read_exact(&mut size)?;
                let size = u16::from_le_bytes(size) as usize;
                if size == 0 {
                    return Err(invalid(
                        "zero compressed chunk size; try old compression mode (-O)",
                    ));
                }
                let mut chunk = vec![0; size + 1];
                reader.read_exact(&mut chunk[..size])?;
                emit(&inflate_chunk(&chunk, false)?)?;
            }
        } else {
            let mut buffered = BufReader::new(reader);
            let mut chunk = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                if buffered.read(&mut byte)? == 0 {
                    if !chunk.is_empty() {
                        return Err(invalid("missing legacy end-of-chunk marker"));
                    }
                    break;
                }
                chunk.push(byte[0]);
                if chunk.len() > 1024 * 1024 {
                    return Err(invalid("legacy compressed chunk exceeds 1 MiB"));
                }
                if chunk.ends_with(&MARKER) {
                    // Some Smacker files contain marker bytes inside compressed data.
                    // Match upstream's test of the following DEFLATE block's first bit.
                    let following = buffered.fill_buf()?;
                    if following.first().is_some_and(|b| b & 1 != 0) {
                        continue;
                    }
                    emit(&inflate_chunk(&chunk, true)?)?;
                    chunk.clear();
                }
            }
        }
        if written != file.expanded_size {
            return Err(invalid(format!(
                "expanded size mismatch: expected {}, got {written}",
                file.expanded_size
            )));
        }
        if mode == Compression::New
            && self.metadata.major_version >= 6
            && digest.finalize().0 != file.md5
        {
            return Err(Error::Checksum(index));
        }
        Ok(())
    }
    pub fn extract(&self, index: usize, mode: Compression) -> Result<Vec<u8>> {
        let index = self.resolve_link(index)?;
        let file = self.file(index)?;
        let size = if mode == Compression::Raw {
            file.compressed_size.max(file.expanded_size)
        } else {
            file.expanded_size
        };
        if size > 512 * 1024 * 1024 {
            return Err(invalid("use extract_to for files larger than 512 MiB"));
        }
        let mut output = Vec::new();
        self.extract_to(index, &mut output, mode)?;
        Ok(output)
    }
    pub fn save(&self, index: usize, path: Option<&Path>, mode: Compression) -> Result<()> {
        // Validate the member and open its input before truncating a caller's output.
        let index = self.resolve_link(index)?;
        let reader = Payload::new(self, index, mode)?;
        if let Some(path) = path {
            let mut writer = self.io.create(path)?;
            self.extract_payload(index, reader, writer.as_mut(), mode)?;
            writer.flush()?;
        } else {
            self.extract_payload(index, reader, &mut io::sink(), mode)?;
        }
        Ok(())
    }
}

fn inflate_chunk(input: &[u8], old: bool) -> Result<Vec<u8>> {
    let mut decoder = Decompress::new(false);
    let mut output = vec![0u8; BLOCK_SIZE + 1];
    let status = decoder
        .decompress(
            input,
            &mut output,
            if old {
                FlushDecompress::Sync
            } else {
                FlushDecompress::Finish
            },
        )
        .map_err(|e| invalid(format!("DEFLATE error: {e}")))?;
    let n = decoder.total_out() as usize;
    if n > BLOCK_SIZE {
        return Err(invalid("expanded chunk exceeds 64 KiB"));
    }
    if (!old && status != Status::StreamEnd) || (old && decoder.total_in() as usize != input.len())
    {
        return Err(invalid("incomplete DEFLATE chunk"));
    }
    if !old && (decoder.total_in() as usize) < input.len() - 1 {
        return Err(invalid("trailing data in DEFLATE chunk"));
    }
    output.truncate(n);
    Ok(output)
}

struct Volume {
    first: u32,
    last: u32,
    first_offset: u64,
    first_expanded: u64,
    first_compressed: u64,
    last_offset: Option<u64>,
    last_expanded: u64,
    last_compressed: u64,
}
fn volume_header(input: &mut dyn ReadSeek, major: u32) -> Result<Volume> {
    input.seek(SeekFrom::Start(0))?;
    let mut data = vec![0; if major <= 5 { 60 } else { 84 }];
    input.read_exact(&mut data)?;
    let b = Bytes(&data);
    if b.u32(0)? != format::SIGNATURE {
        return Err(invalid("invalid cabinet volume signature"));
    }
    if major <= 5 {
        Ok(Volume {
            first: b.u32(28)?,
            last: b.u32(32)?,
            first_offset: b.u32(36)? as u64,
            first_expanded: b.u32(40)? as u64,
            first_compressed: b.u32(44)? as u64,
            last_offset: match b.u32(48)? {
                0 => None,
                v => Some(v as u64),
            },
            last_expanded: b.u32(52)? as u64,
            last_compressed: b.u32(56)? as u64,
        })
    } else {
        Ok(Volume {
            first: b.u32(28)?,
            last: b.u32(32)?,
            first_offset: b.u64(36)?,
            first_expanded: b.u64(44)?,
            first_compressed: b.u64(52)?,
            last_offset: Some(b.u64(60)?),
            last_expanded: b.u64(68)?,
            last_compressed: b.u64(76)?,
        })
    }
}
struct Payload<'a> {
    archive: &'a Archive,
    index: usize,
    file: &'a FileEntry,
    input: Box<dyn ReadSeek>,
    volume: u16,
    segment_left: u64,
    remaining: u64,
    split: bool,
    seed: u32,
    external: bool,
}
impl<'a> Payload<'a> {
    fn new(archive: &'a Archive, index: usize, mode: Compression) -> Result<Self> {
        let file = archive.file(index)?;
        let mut volume = file.volume.max(1);
        let (mut input, vh) = loop {
            let mut input = archive.io.open(&archive.volume_path(volume)?)?;
            let vh = volume_header(input.as_mut(), archive.metadata.major_version)?;
            if archive.metadata.major_version <= 5 && index as u32 > vh.last {
                volume = volume
                    .checked_add(1)
                    .ok_or_else(|| invalid("volume number overflow"))?;
                continue;
            }
            break (input, vh);
        };
        let remaining = if file.flags & FILE_COMPRESSED != 0 {
            file.compressed_size
        } else {
            file.expanded_size
        };
        let file_len = input.seek(SeekFrom::End(0))?;
        if remaining != 0 && file_len == file.data_offset && mode == Compression::Old {
            let dir = archive
                .metadata
                .directories
                .get(file.directory_index)
                .ok_or_else(|| invalid("bad external directory"))?;
            let member = if dir.is_empty() {
                file.name.clone()
            } else {
                format!("{dir}/{}", file.name)
            };
            safe_relative(&member)?;
            let mut bytes = archive.metadata.directory_bytes[file.directory_index].clone();
            if !bytes.is_empty() {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(&file.name_bytes);
            for byte in &mut bytes {
                if *byte == b'\\' {
                    *byte = b'/';
                }
            }
            let rel = crate::ffi::narrow_path(&bytes)?;
            input = archive
                .io
                .open(&archive.io.find(&archive.directory.join(rel))?)?;
            let len = input.seek(SeekFrom::End(0))?;
            input.seek(SeekFrom::Start(0))?;
            // Upstream repairs up to four missing marker bytes for external compressed files.
            if file.flags & FILE_COMPRESSED != 0 && len < remaining {
                let missing = (remaining - len).min(4) as usize;
                input = Box::new(PaddedFile {
                    inner: input,
                    length: len,
                    position: 0,
                    tail: MARKER[4 - missing..].to_vec(),
                });
                let remaining = len + missing as u64;
                return Ok(Self {
                    archive,
                    index,
                    file,
                    input,
                    volume,
                    segment_left: remaining,
                    remaining,
                    split: false,
                    seed: 0,
                    external: true,
                });
            }
            return Ok(Self {
                archive,
                index,
                file,
                input,
                volume,
                segment_left: remaining,
                remaining,
                split: false,
                seed: 0,
                external: true,
            });
        }
        let inferred = archive.metadata.major_version == 5
            && ((index + 1 < archive.files().len()
                && index as u32 == vh.last
                && vh.last_compressed != file.compressed_size)
                || (index > 0
                    && index as u32 == vh.first
                    && vh.first_compressed != file.compressed_size));
        let split = file.flags & FILE_SPLIT != 0 || inferred;
        let mut result = Self {
            archive,
            index,
            file,
            input,
            volume,
            segment_left: 0,
            remaining,
            split,
            seed: 0,
            external: false,
        };
        result.set_segment(vh)?;
        Ok(result)
    }
    fn set_segment(&mut self, vh: Volume) -> Result<()> {
        let compressed = self.file.flags & FILE_COMPRESSED != 0;
        let (offset, bytes) = if self.split {
            if let Some(offset) = vh.last_offset.filter(|_| self.index as u32 == vh.last) {
                (
                    offset,
                    if compressed {
                        vh.last_compressed
                    } else {
                        vh.last_expanded
                    },
                )
            } else if self.index as u32 == vh.first {
                (
                    vh.first_offset,
                    if compressed {
                        vh.first_compressed
                    } else {
                        vh.first_expanded
                    },
                )
            } else {
                return Err(invalid("split file absent from volume boundaries"));
            }
        } else {
            (self.file.data_offset, self.remaining)
        };
        if bytes == 0 && self.remaining != 0 {
            return Err(invalid("empty volume segment"));
        }
        let end = offset
            .checked_add(bytes)
            .ok_or_else(|| invalid("volume segment size overflow"))?;
        let len = self.input.seek(SeekFrom::End(0))?;
        if end > len {
            return Err(invalid("file payload extends beyond cabinet volume"));
        }
        self.input.seek(SeekFrom::Start(offset))?;
        self.segment_left = bytes.min(self.remaining);
        Ok(())
    }
    fn next_volume(&mut self) -> Result<()> {
        if !self.split || self.external {
            return Err(invalid("unexpected end of file payload"));
        }
        self.volume = self
            .volume
            .checked_add(1)
            .ok_or_else(|| invalid("volume number overflow"))?;
        self.input = self
            .archive
            .io
            .open(&self.archive.volume_path(self.volume)?)?;
        let vh = volume_header(self.input.as_mut(), self.archive.metadata.major_version)?;
        self.set_segment(vh)
    }
}

// Expose a repaired legacy marker without copying an entire external file.
struct PaddedFile {
    inner: Box<dyn ReadSeek>,
    length: u64,
    position: u64,
    tail: Vec<u8>,
}
impl Read for PaddedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position < self.length {
            let size = buffer
                .len()
                .min((self.length - self.position).min(usize::MAX as u64) as usize);
            let n = self.inner.read(&mut buffer[..size])?;
            self.position += n as u64;
            return Ok(n);
        }
        let offset = (self.position - self.length).min(self.tail.len() as u64) as usize;
        let size = buffer.len().min(self.tail.len() - offset);
        buffer[..size].copy_from_slice(&self.tail[offset..offset + size]);
        self.position += size as u64;
        Ok(size)
    }
}
impl Seek for PaddedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let total = self.length + self.tail.len() as u64;
        let next = match position {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.position.checked_add_signed(n),
            SeekFrom::End(n) => total.checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid padded file offset"))?;
        self.inner.seek(SeekFrom::Start(next.min(self.length)))?;
        self.position = next;
        Ok(next)
    }
}
impl Read for Payload<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        if self.segment_left == 0 {
            self.next_volume()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        let n = buffer
            .len()
            .min(self.segment_left.min(self.remaining).min(usize::MAX as u64) as usize);
        self.input.read_exact(&mut buffer[..n])?;
        self.remaining -= n as u64;
        self.segment_left -= n as u64;
        if self.file.flags & FILE_OBFUSCATED != 0 {
            deobfuscate(&mut buffer[..n], &mut self.seed);
        }
        Ok(n)
    }
}

/// Validate an archive path before joining it to an output or external-file directory.
pub fn safe_relative(name: &str) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    if name.starts_with(['/', '\\']) {
        return Err(invalid("absolute member path"));
    }
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') || part.contains('\0') {
            return Err(invalid("unsafe member path"));
        }
        #[cfg(windows)]
        {
            // Win32 normalizes trailing dots/spaces and interprets DOS device
            // names even with extensions; neither denotes an ordinary member.
            let stem = part
                .split('.')
                .next()
                .unwrap_or("")
                .trim_end_matches(' ')
                .to_uppercase();
            let device = matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
            ) || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            });
            if device
                || part.ends_with(['.', ' '])
                || part.chars().any(|c| c < ' ' || "<>\"|?*".contains(c))
            {
                return Err(invalid("unsafe member path on Windows"));
            }
        }
        result.push(part);
    }
    if result.as_os_str().is_empty() {
        return Err(invalid("empty member path"));
    }
    Ok(result)
}
