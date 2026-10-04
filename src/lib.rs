//! InstallShield CAB reader and ABI-compatible replacement for libunshield.
//! Parsing and extraction use safe Rust; C pointer access is confined to `ffi`.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
mod archive;
mod error;
#[allow(unsafe_code)]
pub mod ffi;
mod format;
pub mod io;
pub use archive::{deobfuscate, safe_relative, Archive, Compression};
pub use error::{Error, Result};
pub use format::{
    Component, FileEntry, FileGroup, Metadata, FILE_COMPRESSED, FILE_INVALID, FILE_OBFUSCATED,
    FILE_SPLIT,
};
