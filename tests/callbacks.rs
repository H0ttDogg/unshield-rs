mod common;

use common::fixture_with_payload;
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_long, c_void, CStr},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    ptr,
};
use unshield::ffi::*;

#[derive(Clone, Copy, Default)]
enum Failure {
    #[default]
    None,
    Open,
    Read,
    ReadCount,
    Seek,
    Tell,
    Create,
    Write,
    WriteCount,
    Directory,
    EmptyDirectory,
}

#[derive(Default)]
struct State {
    files: BTreeMap<Vec<u8>, Vec<u8>>,
    opened: usize,
    closed: usize,
    dirs_opened: usize,
    dirs_closed: usize,
    failure: Failure,
}
struct File {
    path: Vec<u8>,
    cursor: Cursor<Vec<u8>>,
    output: bool,
}
#[cfg(unix)]
type Entry = libc::dirent;
#[cfg(windows)]
#[repr(C)]
struct Entry {
    d_ino: c_long,
    d_reclen: u16,
    d_namlen: usize,
    d_type: c_int,
    d_name: [c_char; 260],
}
struct Directory {
    names: std::vec::IntoIter<Vec<u8>>,
    entry: Entry,
}

// Each pointer is a Box allocated by the matching open callback. Userdata points
// to a live State until the archive and all callback resources have been closed.
unsafe extern "C" fn open(
    path: *const c_char,
    mode: *const c_char,
    data: *mut c_void,
) -> *mut c_void {
    let state = unsafe { &mut *data.cast::<State>() };
    let output = unsafe { CStr::from_ptr(mode) }.to_bytes() == b"wb";
    if matches!(state.failure, Failure::Open)
        || (output && matches!(state.failure, Failure::Create))
    {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }.to_bytes();
    let path = path
        .strip_prefix(b"./")
        .or_else(|| path.strip_prefix(b".\\"))
        .unwrap_or(path)
        .to_vec();
    let bytes = if output {
        Vec::new()
    } else if let Some(bytes) = state.files.get(&path) {
        bytes.clone()
    } else {
        return ptr::null_mut();
    };
    state.opened += 1;
    Box::into_raw(Box::new(File {
        path,
        cursor: Cursor::new(bytes),
        output,
    }))
    .cast()
}
unsafe extern "C" fn close(file: *mut c_void, data: *mut c_void) -> c_int {
    let file = unsafe { Box::from_raw(file.cast::<File>()) };
    let state = unsafe { &mut *data.cast::<State>() };
    state.closed += 1;
    if file.output {
        state.files.insert(file.path, file.cursor.into_inner());
    }
    0
}
unsafe extern "C" fn read(
    buffer: *mut c_void,
    size: usize,
    count: usize,
    file: *mut c_void,
    data: *mut c_void,
) -> usize {
    let state = unsafe { &*data.cast::<State>() };
    match state.failure {
        Failure::Read => return 0,
        Failure::ReadCount => return count + 1,
        _ => {}
    }
    if size == 0 || count == 0 {
        return 0;
    }
    let file = unsafe { &mut *file.cast::<File>() };
    let buffer = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), size * count) };
    // Deliberately short reads exercise the adapter's read_exact loops.
    let length = buffer.len().min(113);
    file.cursor.read(&mut buffer[..length]).unwrap_or(0) / size
}
unsafe extern "C" fn write(
    buffer: *const c_void,
    size: usize,
    count: usize,
    file: *mut c_void,
    data: *mut c_void,
) -> usize {
    let state = unsafe { &*data.cast::<State>() };
    match state.failure {
        Failure::Write => return 0,
        Failure::WriteCount => return count + 1,
        _ => {}
    }
    if size == 0 || count == 0 {
        return 0;
    }
    let file = unsafe { &mut *file.cast::<File>() };
    let buffer = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), size * count) };
    file.cursor.write(buffer).unwrap_or(0) / size
}
// C long is 32-bit on Windows and 64-bit on Unix CI targets.
#[allow(clippy::unnecessary_cast)]
unsafe extern "C" fn seek(
    file: *mut c_void,
    offset: c_long,
    whence: c_int,
    data: *mut c_void,
) -> c_int {
    if matches!(unsafe { &*data.cast::<State>() }.failure, Failure::Seek) {
        return -1;
    }
    let pos = match whence {
        0 if offset >= 0 => SeekFrom::Start(offset as u64),
        1 => SeekFrom::Current(offset as i64),
        2 => SeekFrom::End(offset as i64),
        _ => return -1,
    };
    if unsafe { &mut *file.cast::<File>() }
        .cursor
        .seek(pos)
        .is_ok()
    {
        0
    } else {
        -1
    }
}
unsafe extern "C" fn tell(file: *mut c_void, data: *mut c_void) -> c_long {
    if matches!(unsafe { &*data.cast::<State>() }.failure, Failure::Tell) {
        return -1;
    }
    c_long::try_from(unsafe { &*file.cast::<File>() }.cursor.position()).unwrap_or(-1)
}
unsafe extern "C" fn opendir(_path: *const c_char, data: *mut c_void) -> *mut c_void {
    let state = unsafe { &mut *data.cast::<State>() };
    if matches!(state.failure, Failure::Directory) {
        return ptr::null_mut();
    }
    let names = if matches!(state.failure, Failure::EmptyDirectory) {
        Vec::new()
    } else {
        state.files.keys().cloned().collect::<Vec<_>>()
    };
    state.dirs_opened += 1;
    // The native/Windows ABI dirent consists of integer fields and a name buffer;
    // zero is a valid initialized value for every field.
    let entry = unsafe { std::mem::zeroed() };
    Box::into_raw(Box::new(Directory {
        names: names.into_iter(),
        entry,
    }))
    .cast()
}
unsafe extern "C" fn readdir(directory: *mut c_void, _data: *mut c_void) -> *mut c_void {
    let dir = unsafe { &mut *directory.cast::<Directory>() };
    let Some(name) = dir.names.next() else {
        return ptr::null_mut();
    };
    dir.entry.d_name.fill(0);
    for (to, from) in dir.entry.d_name.iter_mut().zip(&name) {
        *to = *from as c_char;
    }
    ptr::addr_of_mut!(dir.entry).cast()
}
unsafe extern "C" fn closedir(directory: *mut c_void, data: *mut c_void) -> c_int {
    drop(unsafe { Box::from_raw(directory.cast::<Directory>()) });
    unsafe { &mut *data.cast::<State>() }.dirs_closed += 1;
    0
}
fn table() -> UnshieldIoCallbacks {
    UnshieldIoCallbacks {
        fopen: Some(open),
        fseek: Some(seek),
        ftell: Some(tell),
        fread: Some(read),
        fwrite: Some(write),
        fclose: Some(close),
        opendir: Some(opendir),
        closedir: Some(closedir),
        readdir: Some(readdir),
    }
}

const PAYLOAD: &[u8] = b"small callback payload\n";
struct Scenario {
    data: *mut State,
    archive: *mut Unshield,
}
impl Scenario {
    fn new(failure: Failure) -> Self {
        let fixture = fixture_with_payload(17, 0, PAYLOAD.to_vec());
        let mut state = Box::new(State {
            failure,
            ..State::default()
        });
        state.files.insert(b"DATA1.HDR".to_vec(), fixture.header);
        state.files.insert(b"DATA1.CAB".to_vec(), fixture.cabinet);
        Self {
            data: Box::into_raw(state),
            archive: ptr::null_mut(),
        }
    }
    fn open(&mut self, force: bool) {
        let callbacks = table();
        self.archive = unsafe {
            if force {
                unshield_open2_force_version(
                    c"data1.cab".as_ptr(),
                    17,
                    &callbacks,
                    self.data.cast(),
                )
            } else {
                unshield_open2(c"data1.cab".as_ptr(), &callbacks, self.data.cast())
            }
        };
        // The local table is gone when subsequent save/close calls use its copy.
    }
    fn state(&mut self) -> &mut State {
        unsafe { &mut *self.data }
    }
}
impl Drop for Scenario {
    fn drop(&mut self) {
        unsafe { unshield_close(self.archive) };
        let state = unsafe { Box::from_raw(self.data) };
        assert_eq!(state.opened, state.closed, "file lifetime imbalance");
        assert_eq!(
            state.dirs_opened, state.dirs_closed,
            "directory lifetime imbalance"
        );
    }
}

#[test]
fn callback_table_and_directory_entries_live_through_extraction() {
    for force in [false, true] {
        let mut scenario = Scenario::new(Failure::None);
        scenario.open(force);
        assert!(!scenario.archive.is_null());
        unsafe {
            assert!(unshield_file_save(scenario.archive, 0, c"output".as_ptr()));
            assert!(unshield_file_save(scenario.archive, 0, ptr::null()));
            assert!(unshield_file_save_old(scenario.archive, 0, c"old".as_ptr()));
            assert!(unshield_file_save_raw(scenario.archive, 0, c"raw".as_ptr()));
        }
        for name in [b"output".as_slice(), b"old", b"raw"] {
            assert_eq!(scenario.state().files[name], PAYLOAD);
        }
        assert!(scenario.state().dirs_opened >= 4);
        let state = scenario.state();
        assert_eq!(state.opened, state.closed);
    }
}

#[test]
fn callback_failures_release_every_file_and_directory() {
    for failure in [
        Failure::Open,
        Failure::Read,
        Failure::ReadCount,
        Failure::Seek,
        Failure::Tell,
        Failure::EmptyDirectory,
    ] {
        let mut scenario = Scenario::new(failure);
        scenario.open(false);
        assert!(scenario.archive.is_null());
    }
    for failure in [
        Failure::Read,
        Failure::ReadCount,
        Failure::Seek,
        Failure::Tell,
        Failure::Create,
        Failure::Write,
        Failure::WriteCount,
        Failure::EmptyDirectory,
    ] {
        let mut scenario = Scenario::new(Failure::None);
        scenario.open(false);
        assert!(!scenario.archive.is_null());
        scenario.state().failure = failure;
        assert!(!unsafe { unshield_file_save(scenario.archive, 0, c"output".as_ptr()) });
    }
    // A failed directory open falls back to direct fopen, matching upstream.
    let mut scenario = Scenario::new(Failure::None);
    scenario.open(false);
    scenario.state().failure = Failure::Directory;
    let state = scenario.state();
    state.files.insert(
        b"data1.cab".to_vec(),
        state.files[b"DATA1.CAB".as_slice()].clone(),
    );
    assert!(unsafe { unshield_file_save(scenario.archive, 0, c"output".as_ptr()) });
    assert_eq!(scenario.state().files[b"output".as_slice()], PAYLOAD);
}

#[test]
fn incomplete_callback_table_is_rejected_before_opening() {
    let mut scenario = Scenario::new(Failure::None);
    let mut callbacks = table();
    callbacks.fread = None;
    let handle = unsafe { unshield_open2(c"data1.cab".as_ptr(), &callbacks, scenario.data.cast()) };
    assert!(handle.is_null());
    assert_eq!(scenario.state().opened, 0);
    assert_eq!(scenario.state().dirs_opened, 0);
}
