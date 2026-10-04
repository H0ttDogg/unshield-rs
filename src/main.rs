#![forbid(unsafe_code)]
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use unshield::{Archive, Compression, Error, Result};

fn usage() {
    println!("Usage: unshield [-O | -r] [-d DIR] [-g GROUP] [-c COMPONENT] [-i VERSION] [-j] <c|g|l|t|x> CAB [FILENAME...]\n\
        c: list components   g: list groups   l: list files   t: test files   x: extract\n\
        -O: legacy compression   -r: raw payload   -j: flatten directories");
}
fn fail(message: impl Into<String>) -> Error {
    Error::Format(message.into())
}
fn safe_part(name: &str) -> Result<PathBuf> {
    if !name.starts_with(['/', '\\'])
        && name
            .split(['/', '\\'])
            .all(|part| part.is_empty() || part == ".")
    {
        return Ok(PathBuf::new());
    }
    unshield::safe_relative(name)
}
fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Junctions and other reparse points can redirect writes, too.
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
// Reject existing symlinks before creating an output. The CLI assumes the destination
// is not concurrently modified by another process; it does not provide a sandbox.
fn prepare_output(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut current = root.to_owned();
    let parts = relative.components().collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err(fail("unsafe member path"));
        }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if is_link(&meta) => {
                return Err(fail("output path contains a symlink or reparse point"))
            }
            Ok(meta)
                if (i + 1 == parts.len() && !meta.is_file())
                    || (i + 1 < parts.len() && !meta.is_dir()) =>
            {
                return Err(fail("output path is not a regular file/directory"))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if i + 1 < parts.len() {
                    fs::create_dir(&current)?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(current)
}
// Only replace an existing destination after successful extraction and checksum
// verification. A separate inode also prevents overwriting existing hardlinks.
fn save_member(
    archive: &Archive,
    index: usize,
    destination: &Path,
    mode: Compression,
) -> Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let parent = destination
        .parent()
        .ok_or_else(|| fail("missing output parent"))?;
    for _ in 0..128 {
        let path = parent.join(format!(
            ".unshield-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if path == destination {
            continue;
        }
        let writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path);
        let mut writer = match writer {
            Ok(writer) => writer,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        let temporary = Temporary(path);
        let result = archive
            .extract_to(index, &mut writer, mode)
            .and_then(|()| writer.flush().map_err(Error::from));
        drop(writer); // Windows requires closing the temporary before rename/delete.
        result?;
        fs::rename(&temporary.0, destination)?;
        return Ok(());
    }
    Err(fail("could not create a temporary output file"))
}
fn run() -> Result<()> {
    // Return an ordinary error, rather than panic, for unsupported non-UTF-8 arguments.
    let mut args = env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| fail("command-line arguments must be UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter();
    let mut output = PathBuf::from(".");
    let mut mode = Compression::New;
    let mut version = None;
    let mut group = None;
    let mut component = None;
    let mut flat = false;
    let mut lower = false;
    let mut positional = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            "-V" | "--version" => {
                println!("unshield-rs {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-O" => mode = Compression::Old,
            "-r" => mode = Compression::Raw,
            "-j" => flat = true,
            "-d" => {
                output = PathBuf::from(args.next().ok_or_else(|| fail("-d needs a directory"))?)
            }
            "-g" => group = Some(args.next().ok_or_else(|| fail("-g needs a group"))?),
            "-c" => component = Some(args.next().ok_or_else(|| fail("-c needs a component"))?),
            "-i" => {
                version = Some(
                    args.next()
                        .ok_or_else(|| fail("-i needs a version"))?
                        .parse::<u32>()
                        .map_err(|_| fail("invalid version"))?,
                )
            }
            "-L" => lower = true,
            "-R" => {}
            "-D" => {
                let level = args
                    .next()
                    .ok_or_else(|| fail("-D needs a level"))?
                    .parse::<i32>()
                    .map_err(|_| fail("invalid log level"))?;
                unshield::ffi::unshield_set_log_level(level);
            }
            _ if arg.starts_with('-') => return Err(fail(format!("unknown option {arg}"))),
            _ => positional.push(arg),
        }
    }
    if positional.len() < 2 {
        usage();
        return Err(fail("expected command and cabinet filename"));
    }
    let archive = if let Some(v) = version {
        Archive::open_force_version(&positional[1], v)?
    } else {
        Archive::open(&positional[1])?
    };
    let meta = archive.metadata();
    match positional[0].as_str() {
        "c" => {
            for c in &meta.components {
                println!("{}", c.name);
            }
            return Ok(());
        }
        "g" => {
            for g in &meta.file_groups {
                println!("{}", g.name);
            }
            return Ok(());
        }
        "l" | "t" | "x" => {}
        _ => return Err(fail("unknown command")),
    }
    if let Some(name) = &group {
        if !meta.file_groups.iter().any(|g| &g.name == name) {
            return Err(fail("file group not found"));
        }
    }
    let component = component
        .map(|name| {
            meta.components
                .iter()
                .find(|c| c.name == name)
                .ok_or_else(|| fail("component not found"))
        })
        .transpose()?;
    if positional[0] == "x" {
        fs::create_dir_all(&output)?;
        output = fs::canonicalize(output)?;
    }
    let mut failures = 0;
    let mut count = 0;
    for (i, file) in archive.files().iter().enumerate() {
        if !file.is_valid() {
            continue;
        }
        if positional.len() > 2 && !positional[2..].iter().any(|n| n == &file.name) {
            continue;
        }
        let member_group = meta.file_groups.iter().find(|g| {
            g.first_file >= 0
                && i >= g.first_file as usize
                && i <= g.last_file as usize
                && group.as_ref().is_none_or(|name| &g.name == name)
                && component.is_none_or(|c| c.file_groups.contains(&g.name))
        });
        if (group.is_some() || component.is_some()) && member_group.is_none() {
            continue;
        }
        let directory = &meta.directories[file.directory_index];
        let result = match positional[0].as_str() {
            "l" => {
                println!("{:>12}  {directory}\\{}", file.expanded_size, file.name);
                Ok(())
            }
            "t" => archive.extract_to(i, &mut std::io::sink(), mode),
            "x" => (|| {
                let mut relative = PathBuf::new();
                if !flat {
                    if let Some(g) = member_group {
                        relative.push(safe_part(&g.name)?);
                    }
                    relative.push(safe_part(directory)?);
                }
                relative.push(unshield::safe_relative(&file.name)?);
                if lower {
                    relative = PathBuf::from(relative.to_string_lossy().to_lowercase());
                }
                if relative.as_os_str().is_empty() {
                    return Err(fail("empty member path"));
                }
                let destination = prepare_output(&output, &relative)?;
                println!("  extracting: {}", destination.display());
                save_member(&archive, i, &destination, mode)
            })(),
            _ => unreachable!(),
        };
        if let Err(e) = result {
            eprintln!("{}: {e}", file.name);
            failures += 1;
        } else {
            count += 1;
        }
    }
    if failures > 0 {
        return Err(fail(format!("{failures} files failed; {count} succeeded")));
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("unshield: {e}");
        std::process::exit(1);
    }
}
