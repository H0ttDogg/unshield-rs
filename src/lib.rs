//! InstallShield CAB reader and ABI-compatible replacement for libunshield.
//! Parsing and extraction use safe Rust; C pointer access is confined to `ffi`.
mod archive;
mod error;
pub mod ffi;
mod format;
pub mod io;
pub use archive::{deobfuscate, Archive, Compression};
pub use error::{Error, Result};
pub use format::{
    Component, FileEntry, FileGroup, Metadata, FILE_COMPRESSED, FILE_INVALID, FILE_OBFUSCATED,
    FILE_SPLIT,
};
