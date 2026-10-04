//! C ABI matching `include/libunshield.h`.
//!
//! Safety contract for exported functions: non-null pointers must address live,
//! correctly aligned objects of the declared type. Strings must be NUL terminated.
//! Handles and borrowed strings/structs live until `unshield_close`; the caller must
//! synchronize access and must not free returned pointers. Callback userdata must
//! outlive the handle. These are the same ownership requirements as libunshield.
#![allow(clippy::missing_safety_doc)]

use crate::{
    io::{CabinetIo, ReadSeek},
    Archive, Compression, Error, Result,
};
use std::{
    ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString},
    io::{self, Read, Seek, SeekFrom, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    ptr,
    rc::Rc,
    sync::atomic::{AtomicI32, Ordering},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnshieldIoCallbacks {
    pub fopen:
        Option<unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> *mut c_void>,
    pub fseek: Option<unsafe extern "C" fn(*mut c_void, c_long, c_int, *mut c_void) -> c_int>,
    pub ftell: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_long>,
    pub fread:
        Option<unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void, *mut c_void) -> usize>,
    pub fwrite: Option<
        unsafe extern "C" fn(*const c_void, usize, usize, *mut c_void, *mut c_void) -> usize,
    >,
    pub fclose: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    pub opendir: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> *mut c_void>,
    pub closedir: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    pub readdir: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void>,
}
#[repr(C)]
pub struct UnshieldFileGroup {
    pub name: *const c_char,
    pub first_file: c_int,
    pub last_file: c_int,
}
#[repr(C)]
pub struct UnshieldComponent {
    pub name: *const c_char,
    pub file_group_count: c_uint,
    pub file_group_names: *const *const c_char,
}

/// Opaque to C. CString allocations and group records never move while open.
pub struct Unshield {
    archive: Archive,
    file_names: Vec<CString>,
    directory_names: Vec<CString>,
    component_names: Vec<CString>,
    group_names: Vec<CString>,
    groups: Vec<UnshieldFileGroup>,
}
static LOG_LEVEL: AtomicI32 = AtomicI32::new(4);
fn boundary<T: Copy>(fallback: T, f: impl FnOnce() -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            if LOG_LEVEL.load(Ordering::Relaxed) >= 1 {
                eprintln!("unshield: {e}");
            }
            fallback
        }
        Err(_) => {
            if LOG_LEVEL.load(Ordering::Relaxed) >= 1 {
                eprintln!("unshield: internal panic caught at C boundary");
            }
            fallback
        }
    }
}
fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| crate::error::invalid("embedded NUL"))
}
unsafe fn path(pointer: *const c_char) -> Result<PathBuf> {
    if pointer.is_null() {
        return Err(crate::error::invalid("null filename"));
    }
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    Ok(narrow_path(bytes)?)
}
pub(crate) fn narrow_path(bytes: &[u8]) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(windows)]
    {
        windows_paths::decode(bytes)
    }
}
fn path_cstring(path: &Path) -> io::Result<CString> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let bytes = windows_paths::encode(path)?;
    CString::new(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}
unsafe fn handle<'a>(p: *mut Unshield) -> Result<&'a Unshield> {
    unsafe { p.as_ref() }.ok_or_else(|| crate::error::invalid("null archive handle"))
}
fn index(i: c_int) -> Result<usize> {
    usize::try_from(i).map_err(|_| Error::InvalidIndex(usize::MAX))
}
fn make_handle(archive: Archive) -> Result<*mut Unshield> {
    let meta = archive.metadata();
    let file_names = meta
        .files
        .iter()
        .map(|f| cstring(&f.name_bytes))
        .collect::<Result<Vec<_>>>()?;
    let directory_names = meta
        .directory_bytes
        .iter()
        .map(|s| cstring(s))
        .collect::<Result<Vec<_>>>()?;
    let component_names = meta
        .components
        .iter()
        .map(|c| cstring(&c.name_bytes))
        .collect::<Result<Vec<_>>>()?;
    let group_names = meta
        .file_groups
        .iter()
        .map(|g| cstring(&g.name_bytes))
        .collect::<Result<Vec<_>>>()?;
    let groups = meta
        .file_groups
        .iter()
        .zip(&group_names)
        .map(|(g, n)| UnshieldFileGroup {
            name: n.as_ptr(),
            first_file: g.first_file,
            last_file: g.last_file,
        })
        .collect();
    Ok(Box::into_raw(Box::new(Unshield {
        archive,
        file_names,
        directory_names,
        component_names,
        group_names,
        groups,
    })))
}

#[no_mangle]
pub extern "C" fn unshield_set_log_level(level: c_int) {
    LOG_LEVEL.store(level, Ordering::Relaxed);
}
#[no_mangle]
pub unsafe extern "C" fn unshield_open(filename: *const c_char) -> *mut Unshield {
    unsafe { unshield_open2_force_version(filename, -1, ptr::null(), ptr::null_mut()) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_open_force_version(
    filename: *const c_char,
    version: c_int,
) -> *mut Unshield {
    unsafe { unshield_open2_force_version(filename, version, ptr::null(), ptr::null_mut()) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_open2(
    filename: *const c_char,
    callbacks: *const UnshieldIoCallbacks,
    userdata: *mut c_void,
) -> *mut Unshield {
    unsafe { unshield_open2_force_version(filename, -1, callbacks, userdata) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_open2_force_version(
    filename: *const c_char,
    version: c_int,
    callbacks: *const UnshieldIoCallbacks,
    userdata: *mut c_void,
) -> *mut Unshield {
    boundary(ptr::null_mut(), || {
        let filename = unsafe { path(filename) }?;
        let force = if version == -1 {
            None
        } else {
            Some(u32::try_from(version).map_err(|_| crate::error::invalid("negative version"))?)
        };
        let provider: Rc<dyn CabinetIo> = if let Some(callbacks) = unsafe { callbacks.as_ref() } {
            let cb = *callbacks;
            if cb.fopen.is_none()
                || cb.fseek.is_none()
                || cb.ftell.is_none()
                || cb.fread.is_none()
                || cb.fwrite.is_none()
                || cb.fclose.is_none()
                || cb.opendir.is_none()
                || cb.closedir.is_none()
                || cb.readdir.is_none()
            {
                return Err(crate::error::invalid("incomplete I/O callbacks"));
            }
            Rc::new(CallbackIo {
                callbacks: cb,
                userdata,
            })
        } else {
            Rc::new(crate::io::NativeIo)
        };
        make_handle(Archive::open_with(filename, force, provider)?)
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_close(p: *mut Unshield) {
    boundary((), || {
        if !p.is_null() {
            drop(unsafe { Box::from_raw(p) });
        }
        Ok(())
    });
}
macro_rules! count {
    ($name:ident,$field:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: *mut Unshield) -> c_int {
            boundary(-1, || {
                let n = unsafe { handle(p) }?.archive.metadata().$field.len();
                c_int::try_from(n).map_err(|_| crate::error::invalid("count exceeds C int"))
            })
        }
    };
}
count!(unshield_file_count, files);
count!(unshield_directory_count, directories);
count!(unshield_component_count, components);
count!(unshield_file_group_count, file_groups);
macro_rules! name {
    ($name:ident,$field:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(p: *mut Unshield, i: c_int) -> *const c_char {
            boundary(ptr::null(), || {
                let h = unsafe { handle(p) }?;
                Ok(h.$field
                    .get(index(i)?)
                    .ok_or(Error::InvalidIndex(i as usize))?
                    .as_ptr())
            })
        }
    };
}
name!(unshield_file_name, file_names);
name!(unshield_directory_name, directory_names);
name!(unshield_component_name, component_names);
name!(unshield_file_group_name, group_names);
#[no_mangle]
pub unsafe extern "C" fn unshield_file_group_get(
    p: *mut Unshield,
    i: c_int,
) -> *mut UnshieldFileGroup {
    boundary(ptr::null_mut(), || {
        let h = unsafe { handle(p) }?;
        Ok(h.groups
            .get(index(i)?)
            .ok_or(Error::InvalidIndex(i as usize))? as *const _ as *mut _)
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_group_find(
    p: *mut Unshield,
    name: *const c_char,
) -> *mut UnshieldFileGroup {
    boundary(ptr::null_mut(), || {
        if name.is_null() {
            return Ok(ptr::null_mut());
        }
        let name = unsafe { CStr::from_ptr(name) };
        let h = unsafe { handle(p) }?;
        Ok(h.group_names
            .iter()
            .position(|n| n.as_c_str() == name)
            .map_or(ptr::null_mut(), |i| &h.groups[i] as *const _ as *mut _))
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_is_valid(p: *mut Unshield, i: c_int) -> bool {
    boundary(false, || {
        Ok(unsafe { handle(p) }?.archive.file(index(i)?)?.is_valid())
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_is_unicode(p: *mut Unshield) -> bool {
    boundary(false, || {
        Ok(unsafe { handle(p) }?.archive.metadata().major_version >= 17)
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_directory(p: *mut Unshield, i: c_int) -> c_int {
    boundary(-1, || {
        let d = unsafe { handle(p) }?
            .archive
            .file(index(i)?)?
            .directory_index;
        c_int::try_from(d).map_err(|_| crate::error::invalid("directory index exceeds C int"))
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_size(p: *mut Unshield, i: c_int) -> usize {
    boundary(0, || {
        usize::try_from(unsafe { handle(p) }?.archive.file(index(i)?)?.expanded_size)
            .map_err(|_| crate::error::invalid("file size exceeds size_t"))
    })
}
unsafe fn save(p: *mut Unshield, i: c_int, filename: *const c_char, mode: Compression) -> bool {
    boundary(false, || {
        let filename = if filename.is_null() {
            None
        } else {
            Some(unsafe { path(filename) }?)
        };
        unsafe { handle(p) }?
            .archive
            .save(index(i)?, filename.as_deref(), mode)?;
        Ok(true)
    })
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_save(
    p: *mut Unshield,
    i: c_int,
    filename: *const c_char,
) -> bool {
    unsafe { save(p, i, filename, Compression::New) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_save_old(
    p: *mut Unshield,
    i: c_int,
    filename: *const c_char,
) -> bool {
    unsafe { save(p, i, filename, Compression::Old) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_file_save_raw(
    p: *mut Unshield,
    i: c_int,
    filename: *const c_char,
) -> bool {
    unsafe { save(p, i, filename, Compression::Raw) }
}
#[no_mangle]
pub unsafe extern "C" fn unshield_deobfuscate(buffer: *mut u8, size: usize, seed: *mut c_uint) {
    boundary((), || {
        if size == 0 {
            return Ok(());
        }
        if buffer.is_null() || seed.is_null() || size > isize::MAX as usize {
            return Err(crate::error::invalid("invalid deobfuscation buffer"));
        }
        crate::deobfuscate(
            unsafe { std::slice::from_raw_parts_mut(buffer, size) },
            unsafe { &mut *seed },
        );
        Ok(())
    });
}

#[derive(Clone, Copy)]
struct CallbackIo {
    callbacks: UnshieldIoCallbacks,
    userdata: *mut c_void,
}
struct CallbackFile {
    io: CallbackIo,
    file: *mut c_void,
}
impl CallbackIo {
    fn file(&self, path: &Path, write: bool) -> io::Result<CallbackFile> {
        let path = path_cstring(path)?;
        let mode = if write { c"wb" } else { c"rb" };
        // SAFETY: callback pointers were validated at open; caller owns userdata.
        let file =
            unsafe { (self.callbacks.fopen.unwrap())(path.as_ptr(), mode.as_ptr(), self.userdata) };
        if file.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "fopen callback failed",
            ));
        }
        Ok(CallbackFile { io: *self, file })
    }
}
impl CabinetIo for CallbackIo {
    fn open(&self, path: &Path) -> io::Result<Box<dyn ReadSeek>> {
        Ok(Box::new(self.file(path, false)?))
    }
    fn create(&self, path: &Path) -> io::Result<Box<dyn Write>> {
        Ok(Box::new(self.file(path, true)?))
    }
    fn find(&self, path: &Path) -> io::Result<PathBuf> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dirname = path_cstring(parent)?;
        let directory =
            unsafe { (self.callbacks.opendir.unwrap())(dirname.as_ptr(), self.userdata) };
        if directory.is_null() {
            return Ok(path.to_owned());
        } // Upstream also tries fopen directly.
        struct DirectoryGuard {
            io: CallbackIo,
            directory: *mut c_void,
        }
        impl Drop for DirectoryGuard {
            fn drop(&mut self) {
                unsafe { (self.io.callbacks.closedir.unwrap())(self.directory, self.io.userdata) };
            }
        }
        let _guard = DirectoryGuard {
            io: *self,
            directory,
        };
        let desired = path_cstring(Path::new(path.file_name().unwrap_or_default()))?;
        loop {
            let entry = unsafe { (self.callbacks.readdir.unwrap())(directory, self.userdata) };
            if entry.is_null() {
                break;
            }
            #[cfg(unix)]
            let name = unsafe { CStr::from_ptr((*(entry as *const libc::dirent)).d_name.as_ptr()) };
            #[cfg(windows)]
            let name =
                unsafe { CStr::from_ptr((*(entry as *const WindowsDirent)).d_name.as_ptr()) };
            if name.to_bytes().eq_ignore_ascii_case(desired.to_bytes()) {
                return Ok(parent.join(narrow_path(name.to_bytes())?));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "cabinet not found by readdir callback",
        ))
    }
}
// Match C fopen's ANSI codepage for Windows C filenames.
#[cfg(windows)]
mod windows_paths {
    use super::*;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    #[link(name = "kernel32")]
    extern "system" {
        fn MultiByteToWideChar(
            page: u32,
            flags: u32,
            bytes: *const u8,
            count: c_int,
            wide: *mut u16,
            size: c_int,
        ) -> c_int;
        fn WideCharToMultiByte(
            page: u32,
            flags: u32,
            wide: *const u16,
            count: c_int,
            bytes: *mut u8,
            size: c_int,
            default: *const u8,
            used: *mut c_int,
        ) -> c_int;
    }
    fn count(n: usize) -> io::Result<c_int> {
        c_int::try_from(n).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path too long"))
    }
    pub(super) fn decode(bytes: &[u8]) -> io::Result<PathBuf> {
        if bytes.is_empty() {
            return Ok(PathBuf::new());
        }
        let n = count(bytes.len())?;
        // SAFETY: input length is checked and output is allocated to the queried size.
        let size = unsafe { MultiByteToWideChar(0, 0, bytes.as_ptr(), n, ptr::null_mut(), 0) };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut wide = vec![0u16; size as usize];
        if unsafe { MultiByteToWideChar(0, 0, bytes.as_ptr(), n, wide.as_mut_ptr(), size) } != size
        {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
    }
    pub(super) fn encode(path: &Path) -> io::Result<Vec<u8>> {
        let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.is_empty() {
            return Ok(Vec::new());
        }
        let n = count(wide.len())?;
        // SAFETY: input length is checked and output is allocated to the queried size.
        let size = unsafe {
            WideCharToMultiByte(
                0,
                0,
                wide.as_ptr(),
                n,
                ptr::null_mut(),
                0,
                ptr::null(),
                ptr::null_mut(),
            )
        };
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0u8; size as usize];
        if unsafe {
            WideCharToMultiByte(
                0,
                0,
                wide.as_ptr(),
                n,
                bytes.as_mut_ptr(),
                size,
                ptr::null(),
                ptr::null_mut(),
            )
        } != size
        {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    }
}
// Layout from upstream's bundled win32_msvc/dirent.h (including LLP64 padding).
#[cfg(windows)]
#[repr(C)]
struct WindowsDirent {
    d_ino: c_long,
    d_reclen: u16,
    d_namlen: usize,
    d_type: c_int,
    d_name: [c_char; 260],
}
impl Drop for CallbackFile {
    fn drop(&mut self) {
        unsafe { (self.io.callbacks.fclose.unwrap())(self.file, self.io.userdata) };
    }
}
impl Read for CallbackFile {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            (self.io.callbacks.fread.unwrap())(
                b.as_mut_ptr().cast(),
                1,
                b.len(),
                self.file,
                self.io.userdata,
            )
        };
        if n > b.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fread returned excessive count",
            ));
        }
        Ok(n)
    }
}
impl Write for CallbackFile {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            (self.io.callbacks.fwrite.unwrap())(
                b.as_ptr().cast(),
                1,
                b.len(),
                self.file,
                self.io.userdata,
            )
        };
        if n > b.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fwrite returned excessive count",
            ));
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for CallbackFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (
                i64::try_from(n)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?,
                0,
            ),
            SeekFrom::Current(n) => (n, 1),
            SeekFrom::End(n) => (n, 2),
        };
        let offset = c_long::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds callback long")
        })?;
        if unsafe {
            (self.io.callbacks.fseek.unwrap())(self.file, offset, whence, self.io.userdata)
        } != 0
        {
            return Err(io::Error::other("fseek callback failed"));
        }
        let offset = unsafe { (self.io.callbacks.ftell.unwrap())(self.file, self.io.userdata) };
        u64::try_from(offset).map_err(|_| io::Error::other("ftell callback failed"))
    }
}
