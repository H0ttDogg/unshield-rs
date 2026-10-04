#![forbid(unsafe_code)]
use std::{
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Storage abstraction used by both native files and the C callback adapter.
pub trait CabinetIo {
    fn open(&self, path: &Path) -> std::io::Result<Box<dyn ReadSeek>>;
    fn create(&self, path: &Path) -> std::io::Result<Box<dyn Write>>;
    fn find(&self, path: &Path) -> std::io::Result<PathBuf>;
}
pub struct NativeIo;
impl CabinetIo for NativeIo {
    fn open(&self, path: &Path) -> std::io::Result<Box<dyn ReadSeek>> {
        Ok(Box::new(File::open(path)?))
    }
    fn create(&self, path: &Path) -> std::io::Result<Box<dyn Write>> {
        Ok(Box::new(File::create(path)?))
    }
    fn find(&self, path: &Path) -> std::io::Result<PathBuf> {
        if path.is_file() {
            return Ok(path.to_owned());
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path.file_name().unwrap_or_default().as_encoded_bytes();
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if entry
                .file_name()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(name)
            {
                return Ok(entry.path());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            path.display().to_string(),
        ))
    }
}
