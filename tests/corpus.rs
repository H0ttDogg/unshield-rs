mod common;
use common::*;
use std::{fs, io::Read, path::Path};
use unshield::{Archive, Compression};

fn verify(name: &str, cab: &str, mode: Compression) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("upstream/unshield/test/v0")
        .join(name);
    let zip = fs::File::open(root.join("test_data.zip"))
        .expect("run scripts/fetch-upstream.ps1 or .sh first");
    let mut zip = zip::ZipArchive::new(zip).unwrap();
    let dir = TempDir::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        let path = dir.0.join(entry.enclosed_name().unwrap());
        if entry.is_dir() {
            fs::create_dir_all(path).unwrap();
        } else {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }
    let a = Archive::open(dir.0.join(cab)).unwrap();
    let mut matched = 0;
    let manifest = fs::read_to_string(root.join(format!("{name}.md5"))).unwrap();
    for line in manifest.lines() {
        let (expected, path) = line.split_once("  ./").unwrap();
        let mut found = None;
        for (i, file) in a.files().iter().enumerate().filter(|(_, f)| f.is_valid()) {
            let group = a
                .metadata()
                .file_groups
                .iter()
                .find(|g| {
                    g.first_file >= 0 && i >= g.first_file as usize && i <= g.last_file as usize
                })
                .unwrap();
            let directory = &a.metadata().directories[file.directory_index];
            let sanitize = |s: &str| s.replace([' ', '<', '>', '[', ']'], "_");
            let actual_path = format!(
                "{}/{}/{}",
                sanitize(&group.name),
                sanitize(directory),
                file.name
            )
            .replace('\\', "/")
            .replace("//", "/");
            if actual_path == path {
                found = Some(i);
                break;
            }
        }
        let index = found.unwrap_or_else(|| panic!("missing member {path}"));
        let output = a
            .extract(index, mode)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(format!("{:x}", md5::compute(output)), expected, "{path}");
        matched += 1;
    }
    println!("{name}: {matched} manifest hashes match");
    // Also exercise valid entries that the manifest intentionally does not include.
    for (i, _) in a.files().iter().enumerate().filter(|(_, f)| f.is_valid()) {
        a.extract_to(i, &mut std::io::sink(), mode).unwrap();
    }
}
#[test]
#[ignore = "requires pinned upstream corpus"]
fn avigomanager() {
    verify("avigomanager", "data1.cab", Compression::Old);
}
#[test]
#[ignore = "requires pinned upstream corpus"]
fn feeble_files() {
    verify("the-feeble-files-spanish", "data1.cab", Compression::Old);
}
#[test]
#[ignore = "requires pinned upstream corpus"]
fn baldurs_gate() {
    verify(
        "baldurs_gate_patch_v1_1_4315_international",
        "data1.cab",
        Compression::New,
    );
}
#[test]
#[ignore = "requires pinned upstream corpus"]
fn wireplay() {
    verify(
        "wireplay",
        "dpcb1197-Wireplay/DOS/data1.cab",
        Compression::Old,
    );
}
#[test]
#[ignore = "requires pinned upstream corpus"]
fn historical_cve_path_is_rejected_by_cli() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("upstream/unshield/test/v5/CVE-2015-1386");
    let dir = TempDir::new();
    for old in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_unshield-rs"));
        if old {
            command.arg("-O");
        }
        let output = command
            .arg("-d")
            .arg(&dir.0)
            .arg("x")
            .arg(root.join("data1.cab"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe member path"));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }
}
