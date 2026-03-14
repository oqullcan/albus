use std::{
    fs::{self},
    io::{self, ErrorKind, Read, Write},
    path::Path,
};

use albus::{ensure_non_symlink_path, harden_private_directory, harden_private_file};
use tempfile::NamedTempFile;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(not(windows))]
use std::fs::File;

pub(crate) fn read_limited_file(path: &Path, max_len: u64) -> io::Result<Vec<u8>> {
    ensure_non_symlink_path(path)?;
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("private state file exceeds the configured maximum of {max_len} bytes"),
        ));
    }

    let mut bytes = Vec::new();
    file.take(max_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("private state file exceeds the configured maximum of {max_len} bytes"),
        ));
    }

    Ok(bytes)
}

pub(crate) fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    ensure_non_symlink_path(path)?;
    let parent = ensure_private_parent(path)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| io::Error::new(error.error.kind(), error.error))?;
    harden_private_file(path)?;
    sync_directory(parent)?;
    Ok(())
}

fn ensure_private_parent(path: &Path) -> io::Result<&Path> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    harden_private_directory(parent)?;
    Ok(parent)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let directory = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        directory.sync_all()?;
    }

    #[cfg(not(windows))]
    {
        let directory = File::open(path)?;
        directory.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_limited_file, write_private_file_atomic};
    use tempfile::TempDir;

    #[test]
    fn atomic_private_write_persists_and_replaces_files() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = TempDir::new()?;
        let path = tempdir.path().join("state").join("private.txt");

        write_private_file_atomic(&path, b"first")?;
        assert_eq!(std::fs::read(&path)?, b"first");

        write_private_file_atomic(&path, b"second")?;
        assert_eq!(std::fs::read(&path)?, b"second");
        Ok(())
    }

    #[test]
    fn limited_private_read_rejects_oversized_files() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let path = tempdir.path().join("oversized.bin");
        std::fs::write(&path, vec![0_u8; 33])?;

        let Err(error) = read_limited_file(&path, 32) else {
            return Err("expected oversized read failure".into());
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }
}
