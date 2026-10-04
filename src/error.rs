#![forbid(unsafe_code)]
use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(String),
    UnsupportedVersion(u32),
    InvalidIndex(usize),
    InvalidFile(usize),
    Checksum(usize),
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Format(message.into())
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Format(s) => write!(f, "invalid cabinet: {s}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported InstallShield version {v:#x}"),
            Self::InvalidIndex(i) => write!(f, "invalid file index {i}"),
            Self::InvalidFile(i) => write!(f, "file {i} is not available in the cabinet"),
            Self::Checksum(i) => write!(f, "MD5 checksum failure for file {i}"),
        }
    }
}
impl std::error::Error for Error {}
