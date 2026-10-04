use std::{
    env, fs,
    path::{Path, PathBuf},
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
    if name.starts_with(['/', '\\']) {
        return Err(fail("absolute member path"));
    }
    let mut path = PathBuf::new();
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') || part.contains('\0') {
            return Err(fail("unsafe member path"));
        }
        path.push(part);
    }
    Ok(path)
}
// Reject existing symlinks before creating an output. The CLI assumes the destination
// is not concurrently modified by another process; it does not provide a sandbox.
fn prepare_output(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut current = root.to_owned();
    let parts = relative.components().collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(fail("output path contains a symlink"))
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
fn run() -> Result<()> {
    let mut args = env::args().skip(1);
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
        let member_group = meta
            .file_groups
            .iter()
            .find(|g| g.first_file >= 0 && i >= g.first_file as usize && i <= g.last_file as usize);
        if group
            .as_ref()
            .is_some_and(|name| member_group.is_none_or(|g| &g.name != name))
        {
            continue;
        }
        if component.is_some_and(|c| member_group.is_none_or(|g| !c.file_groups.contains(&g.name)))
        {
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
                relative.push(safe_part(&file.name)?);
                if lower {
                    relative = PathBuf::from(relative.to_string_lossy().to_lowercase());
                }
                if relative.as_os_str().is_empty() {
                    return Err(fail("empty member path"));
                }
                let destination = prepare_output(&output, &relative)?;
                println!("  extracting: {}", destination.display());
                let result = archive.save(i, Some(&destination), mode);
                if result.is_err() {
                    let _ = fs::remove_file(&destination);
                }
                result
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
