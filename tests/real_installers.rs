#![forbid(unsafe_code)]

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    rc::Rc,
};
use unshield::{
    io::{CabinetIo, NativeIo, ReadSeek},
    Archive, Compression, FILE_COMPRESSED, FILE_OBFUSCATED, FILE_SPLIT,
};

const REFERENCE: &str = "cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db";

#[derive(Deserialize)]
struct Inventory {
    schema_version: u32,
    family: String,
    samples: Vec<Sample>,
}
#[derive(Default, Deserialize)]
struct Input {
    path: String,
    sha256: String,
    archive_path: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Sample {
    id: String,
    status: String,
    installer: Input,
    inputs: Vec<Input>,
    entry_cab: String,
    version_file: String,
    raw_version: u32,
    major_version: u32,
    compression: String,
    expected: String,
    expected_valid_members: usize,
    features: HashMap<String, String>,
    descriptor_evidence: Vec<DescriptorEvidence>,
    name_evidence: Vec<NameEvidence>,
    split_evidence: Vec<SplitEvidence>,
}
#[derive(Deserialize)]
struct SplitEvidence {
    index: usize,
    segments: Vec<VolumeSegment>,
}
#[derive(Deserialize)]
struct VolumeSegment {
    path: String,
    volume: u16,
    offset: u64,
    stored_size: u64,
}
#[derive(Deserialize)]
struct NameEvidence {
    group_index: usize,
    name: String,
    valid_members: Vec<usize>,
}
#[derive(Deserialize)]
struct DescriptorEvidence {
    index: usize,
    flags: u16,
    volume: u16,
    link_previous: u32,
    link_next: u32,
    link_flags: u8,
}
#[derive(Deserialize)]
struct Expected {
    sample_id: String,
    reference_revision: String,
    unicode: bool,
    directories_hex: Vec<String>,
    components_hex: Vec<String>,
    groups: Vec<Group>,
    files: Vec<Member>,
}
#[derive(Deserialize)]
struct Group {
    name_hex: String,
    first_file: i32,
    last_file: i32,
}
#[derive(Deserialize)]
struct Member {
    index: usize,
    valid: bool,
    name_hex: String,
    directory_index: i32,
    expanded_size: u64,
    sha256: Option<String>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_owned()
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
fn relative(path: &str) {
    assert!(!path.is_empty());
    assert!(!path.contains(['\\', ':']));
    assert!(Path::new(path)
        .components()
        .all(|c| matches!(c, Component::Normal(_))));
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_file(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            return hex(&hash.finalize());
        }
        hash.update(&buffer[..n]);
    }
}
#[derive(Default)]
struct HashWriter {
    hash: Sha256,
    size: u64,
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hash.update(bytes);
        self.size += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct VolumeProbe {
    opened: RefCell<Vec<PathBuf>>,
    denied: RefCell<Option<PathBuf>>,
}
impl CabinetIo for VolumeProbe {
    fn open(&self, path: &Path) -> io::Result<Box<dyn ReadSeek>> {
        self.opened.borrow_mut().push(path.to_owned());
        if self.denied.borrow().as_deref() == Some(path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "missing continuation volume",
            ));
        }
        NativeIo.open(path)
    }
    fn create(&self, path: &Path) -> io::Result<Box<dyn Write>> {
        NativeIo.create(path)
    }
    fn find(&self, path: &Path) -> io::Result<PathBuf> {
        NativeIo.find(path)
    }
}

fn inventories() -> Vec<Inventory> {
    let mut ids = HashSet::new();
    ["v6-16", "v17-plus"]
        .into_iter()
        .map(|family| {
            let inventory: Inventory = read_json(&root().join(format!("corpus/{family}.json")));
            assert_eq!(inventory.schema_version, 1);
            assert_eq!(inventory.family, family);
            for sample in &inventory.samples {
                assert!(sample
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'));
                assert!(!sample.id.is_empty() && ids.insert(sample.id.clone()));
                assert!(["candidate", "validated"].contains(&sample.status.as_str()));
                if sample.status != "validated" {
                    continue;
                }
                assert!(if family == "v6-16" {
                    (6..=16).contains(&sample.major_version)
                } else {
                    sample.major_version >= 17
                });
                assert!(["old", "new"].contains(&sample.compression.as_str()));
                let mut paths = HashSet::new();
                for input in std::iter::once(&sample.installer).chain(&sample.inputs) {
                    relative(&input.path);
                    if let Some(path) = &input.archive_path {
                        relative(path);
                    }
                    assert!(paths.insert(&input.path));
                    assert_eq!(input.sha256.len(), 64);
                    assert!(input.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
                }
                for path in [&sample.entry_cab, &sample.version_file] {
                    relative(path);
                    assert!(sample.inputs.iter().any(|i| &i.path == path));
                }
                relative(&sample.expected);
                let expected: Expected = read_json(&root().join(&sample.expected));
                assert_eq!(expected.sample_id, sample.id);
                assert_eq!(expected.reference_revision, REFERENCE);
                assert_eq!(expected.unicode, sample.major_version >= 17);
                assert!(sample.expected_valid_members > 0);
                assert_eq!(
                    expected.files.iter().filter(|f| f.valid).count(),
                    sample.expected_valid_members
                );
                for evidence in &sample.name_evidence {
                    assert!(sample.major_version >= 17);
                    assert!(!evidence.name.is_ascii());
                    let group = &expected.groups[evidence.group_index];
                    assert_eq!(group.name_hex, hex(evidence.name.as_bytes()));
                    assert!(group.first_file >= 0 && group.last_file >= group.first_file);
                    let valid_members = expected.files
                        [group.first_file as usize..=group.last_file as usize]
                        .iter()
                        .filter(|f| f.valid)
                        .map(|f| f.index)
                        .collect::<Vec<_>>();
                    assert!(!valid_members.is_empty());
                    assert_eq!(valid_members, evidence.valid_members);
                }
                for evidence in &sample.split_evidence {
                    assert!(sample.major_version >= 6);
                    assert!(expected.files[evidence.index].valid);
                    assert!(evidence.segments.len() >= 2);
                    let mut paths = HashSet::new();
                    for segment in &evidence.segments {
                        relative(&segment.path);
                        assert!(sample.inputs.iter().any(|i| i.path == segment.path));
                        assert!(paths.insert(&segment.path));
                        assert!(segment.offset >= 84 && segment.stored_size > 0);
                    }
                }
                assert_eq!(
                    sample.features.get("split_volumes").map(String::as_str),
                    Some(if sample.split_evidence.is_empty() {
                        "absent"
                    } else {
                        "present"
                    }),
                    "split coverage requires a valid member with segments in multiple inputs"
                );
                for (index, file) in expected.files.iter().enumerate() {
                    assert_eq!(file.index, index, "expected records must cover every index");
                    if file.valid {
                        let hash = file
                            .sha256
                            .as_ref()
                            .expect("valid member needs independent SHA-256");
                        assert_eq!(hash.len(), 64);
                        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
                        assert!(file.directory_index >= 0);
                        assert!((file.directory_index as usize) < expected.directories_hex.len());
                    } else {
                        assert!(file.sha256.is_none());
                    }
                }
            }
            inventory
        })
        .collect()
}

#[test]
fn inventory_contract_is_valid() {
    inventories();
}

#[test]
fn real_installers() {
    let required = std::env::var("UNSHIELD_REQUIRE_REAL_INSTALLERS").unwrap_or_default();
    let mut verified_ids = HashSet::new();
    let mut passed = 0;
    for inventory in inventories() {
        let mut selected = 0;
        for sample in inventory.samples {
            if sample.status != "validated" {
                eprintln!(
                    "SKIP {}: candidate has no verified reference output",
                    sample.id
                );
                continue;
            }
            selected += 1;
            let dir = root().join("test-data/real-installers").join(&sample.id);
            if !dir.is_dir() {
                eprintln!(
                    "SKIP {}: run python3 scripts/real-installers.py fetch",
                    sample.id
                );
                continue;
            }
            for input in std::iter::once(&sample.installer).chain(&sample.inputs) {
                assert_eq!(
                    hash_file(&dir.join(&input.path)),
                    input.sha256,
                    "{}: input {}",
                    sample.id,
                    input.path
                );
            }
            let mut version = [0; 8];
            fs::File::open(dir.join(&sample.version_file))
                .unwrap()
                .read_exact(&mut version)
                .unwrap();
            assert_eq!(&version[..4], b"ISc(");
            assert_eq!(
                u32::from_le_bytes(version[4..].try_into().unwrap()),
                sample.raw_version
            );
            let archive = Archive::open(dir.join(&sample.entry_cab)).unwrap();
            assert_eq!(archive.metadata().major_version, sample.major_version);
            let valid = archive.files().iter().filter(|f| f.is_valid());
            let non_ascii_names = valid.clone().any(|f| !f.name_bytes.is_ascii())
                || archive
                    .metadata()
                    .directory_bytes
                    .iter()
                    .any(|n| !n.is_ascii())
                || archive
                    .metadata()
                    .components
                    .iter()
                    .any(|c| !c.name_bytes.is_ascii())
                || archive
                    .metadata()
                    .file_groups
                    .iter()
                    .any(|g| !g.name_bytes.is_ascii());
            for (feature, present) in [
                ("unicode", sample.major_version >= 17),
                ("non_ascii_names", non_ascii_names),
                (
                    "compression",
                    valid.clone().any(|f| f.flags & FILE_COMPRESSED != 0),
                ),
                (
                    "obfuscation",
                    valid.clone().any(|f| f.flags & FILE_OBFUSCATED != 0),
                ),
                ("links", valid.clone().any(|f| f.link_flags & 1 != 0)),
                (
                    "split_volumes",
                    valid.clone().any(|f| f.flags & FILE_SPLIT != 0),
                ),
            ] {
                assert_eq!(
                    sample.features.get(feature).map(String::as_str),
                    Some(if present { "present" } else { "absent" }),
                    "{}: measured feature {feature}",
                    sample.id
                );
            }
            for evidence in &sample.descriptor_evidence {
                let actual = &archive.files()[evidence.index];
                assert!(
                    actual.is_valid(),
                    "feature evidence must name a valid member"
                );
                assert_eq!(actual.flags, evidence.flags);
                assert_eq!(actual.volume, evidence.volume);
                assert_eq!(actual.link_previous, evidence.link_previous);
                assert_eq!(actual.link_next, evidence.link_next);
                assert_eq!(actual.link_flags, evidence.link_flags);
            }
            for evidence in &sample.split_evidence {
                let file = &archive.files()[evidence.index];
                assert!(file.is_valid() && file.flags & FILE_SPLIT != 0);
                // Linked aliases reuse earlier payloads; measure the physical member.
                assert_eq!(file.link_flags & 1, 0);
                assert_eq!(file.data_offset, evidence.segments[0].offset);
                let compressed = file.flags & FILE_COMPRESSED != 0;
                let mut stored_size = 0;
                for (part, segment) in evidence.segments.iter().enumerate() {
                    assert_eq!(usize::from(segment.volume), usize::from(file.volume) + part);
                    let mut input = fs::File::open(dir.join(&segment.path)).unwrap();
                    let mut header = [0; 84];
                    input.read_exact(&mut header).unwrap();
                    let u32_at = |p| u32::from_le_bytes(header[p..p + 4].try_into().unwrap());
                    let u64_at = |p| u64::from_le_bytes(header[p..p + 8].try_into().unwrap());
                    assert_eq!(&header[..4], b"ISc(");
                    assert_eq!(u32_at(4), sample.raw_version);
                    let (offset, bytes) = if evidence.index == u32_at(32) as usize {
                        (u64_at(60), u64_at(if compressed { 76 } else { 68 }))
                    } else {
                        assert_eq!(evidence.index, u32_at(28) as usize);
                        (u64_at(36), u64_at(if compressed { 52 } else { 44 }))
                    };
                    assert_eq!((offset, bytes), (segment.offset, segment.stored_size));
                    assert!(offset + bytes <= input.metadata().unwrap().len());
                    stored_size += bytes;
                }
                assert_eq!(
                    stored_size,
                    if compressed {
                        file.compressed_size
                    } else {
                        file.expanded_size
                    }
                );
                let probe = Rc::new(VolumeProbe::default());
                let observed =
                    Archive::open_with(dir.join(&sample.entry_cab), None, probe.clone()).unwrap();
                probe.opened.borrow_mut().clear();
                let mut output = HashWriter::default();
                observed
                    .extract_to(evidence.index, &mut output, Compression::New)
                    .unwrap();
                assert_eq!(output.size, file.expanded_size);
                let paths = evidence
                    .segments
                    .iter()
                    .map(|s| dir.join(&s.path))
                    .collect::<Vec<_>>();
                assert_eq!(*probe.opened.borrow(), paths);
                // Removing a continuation through I/O must reject incomplete output.
                *probe.denied.borrow_mut() = paths.last().cloned();
                probe.opened.borrow_mut().clear();
                assert!(observed
                    .extract_to(evidence.index, &mut io::sink(), Compression::New)
                    .is_err());
                assert_eq!(*probe.opened.borrow(), paths);
            }
            let expected: Expected = read_json(&root().join(&sample.expected));
            assert_eq!(
                archive
                    .metadata()
                    .directory_bytes
                    .iter()
                    .map(|b| hex(b))
                    .collect::<Vec<_>>(),
                expected.directories_hex
            );
            assert_eq!(
                archive
                    .metadata()
                    .components
                    .iter()
                    .map(|c| hex(&c.name_bytes))
                    .collect::<Vec<_>>(),
                expected.components_hex
            );
            assert_eq!(archive.metadata().file_groups.len(), expected.groups.len());
            for (actual, expected) in archive.metadata().file_groups.iter().zip(&expected.groups) {
                assert_eq!(hex(&actual.name_bytes), expected.name_hex);
                assert_eq!(actual.first_file, expected.first_file);
                assert_eq!(actual.last_file, expected.last_file);
            }
            assert_eq!(archive.files().len(), expected.files.len());
            let mode = if sample.compression == "old" {
                Compression::Old
            } else {
                Compression::New
            };
            for (actual, expected) in archive.files().iter().zip(&expected.files) {
                assert_eq!(
                    actual.is_valid(),
                    expected.valid,
                    "{} member {} validity",
                    sample.id,
                    expected.index
                );
                // Invalid entries are counted and checked for validity, but are
                // not selected for extraction or valid-member metadata checks.
                if !expected.valid {
                    continue;
                }
                assert_eq!(
                    hex(&actual.name_bytes),
                    expected.name_hex,
                    "member {} name",
                    expected.index
                );
                assert_eq!(actual.directory_index as i32, expected.directory_index);
                assert_eq!(actual.expanded_size, expected.expanded_size);
                let mut writer = HashWriter::default();
                archive
                    .extract_to(expected.index, &mut writer, mode)
                    .unwrap_or_else(|e| panic!("{} member {}: {e}", sample.id, expected.index));
                assert_eq!(writer.size, expected.expanded_size);
                assert_eq!(
                    hex(&writer.hash.finalize()),
                    *expected.sha256.as_ref().unwrap(),
                    "{} member {} content",
                    sample.id,
                    expected.index
                );
            }
            println!("PASS {}: format {}, {} total / {} valid members; all metadata and SHA-256 hashes match", sample.id, sample.major_version, expected.files.len(), sample.expected_valid_members);
            verified_ids.insert(sample.id);
            passed += 1;
        }
        if selected == 0 {
            eprintln!("SKIP {}: no validated sample recorded", inventory.family);
        }
    }
    for id in required.split(',').filter(|s| !s.is_empty()) {
        assert!(
            verified_ids.contains(id),
            "required real sample {id} was not verified"
        );
    }
    println!("Real-installer samples verified: {passed}");
}
