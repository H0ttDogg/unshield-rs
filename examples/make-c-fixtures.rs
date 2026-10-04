#[path = "../tests/common/mod.rs"]
mod common;
fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "target/c-fixtures".into());
    for (version, flags) in [(0, 0), (5, 0), (6, 4), (17, 6)] {
        let f = common::fixture(version, flags);
        let dir = root.join(format!("v{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data1.hdr"), f.header).unwrap();
        std::fs::write(dir.join("data1.cab"), f.cabinet).unwrap();
        std::fs::write(dir.join("expected.bin"), f.payload).unwrap();
    }
    let f = common::fixture(6, 4);
    let embedded = common::embedded(&f);
    let dir = root.join("v6_embedded");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("data1.cab"), embedded).unwrap();
    std::fs::write(dir.join("expected.bin"), f.payload).unwrap();
}
