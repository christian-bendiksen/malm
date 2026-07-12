//! Hardened zip, tar.gz, and tar.xz extraction with entry, size, and
//! depth budgets; rejects traversal, links, special files, setuid, and
//! world-writable modes; clamps permissions after unpack.

use anyhow::{Context, Result};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

const MAX_ENTRIES: u64 = 100_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

/// `stat` file-type bit mask (`S_IFMT`).
const S_IFMT: u32 = 0o170_000;
/// `stat` symbolic-link file type (`S_IFLNK`).
const S_IFLNK: u32 = 0o120_000;

pub fn extract_zip(archive: &Path, dst: &Path) -> Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read zip archive")?;

    if zip.len() as u64 > MAX_ENTRIES {
        anyhow::bail!(
            "archive has too many entries: {} (max {MAX_ENTRIES})",
            zip.len()
        );
    }

    let mut total: u64 = 0;
    let mut directory_modes = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).context("read zip entry")?;

        let entry_path = entry
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("unsafe path in archive: {:?}", entry.name()))?
            .to_owned();
        reject_unsafe_components(&entry_path)?;
        reject_deep_path(&entry_path)?;

        let mode = entry.unix_mode();
        if let Some(mode) = mode {
            reject_unsafe_mode(mode, entry.is_dir(), &entry_path)?;
            if mode & S_IFMT == S_IFLNK {
                anyhow::bail!("archive contains symlink: {}", entry_path.display());
            }
        }

        let dest = dst.join(&entry_path);

        if entry.is_dir() {
            fs::create_dir_all(&dest).with_context(|| format!("create dir {}", dest.display()))?;
            if let Some(mode) = mode {
                directory_modes.push((dest, mode));
            }
        } else {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            let mut out =
                fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
            // Count bytes read from zip data because its size header is untrusted.
            let written = std::io::copy(&mut (&mut entry).take(MAX_FILE_BYTES + 1), &mut out)
                .with_context(|| format!("write {}", dest.display()))?;
            if written > MAX_FILE_BYTES {
                anyhow::bail!(
                    "archive entry exceeds {MAX_FILE_BYTES} bytes: {}",
                    entry_path.display()
                );
            }
            total = total.saturating_add(written);
            if total > MAX_TOTAL_BYTES {
                anyhow::bail!("archive unpacks to more than {MAX_TOTAL_BYTES} bytes");
            }
            drop(out);
            apply_safe_mode(&dest, mode)?;
        }
    }

    // Directory modes are applied last and deepest-first so a read-only
    // parent can't block writing its children.
    for (path, mode) in directory_modes.into_iter().rev() {
        apply_safe_mode(&path, Some(mode))?;
    }

    Ok(())
}

pub fn extract_tar_xz(archive: &Path, dst: &Path) -> Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    unpack_tar(xz2::read::XzDecoder::new(file), dst)
}

pub fn extract_tar_gz(archive: &Path, dst: &Path) -> Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    unpack_tar(flate2::read::GzDecoder::new(file), dst)
}

fn unpack_tar<R: Read>(reader: R, dst: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);

    let mut total: u64 = 0;
    let mut count: u64 = 0;
    for entry in archive.entries().context("read tar archive")? {
        let mut entry = entry.context("read tar entry")?;
        let path = entry.path().context("read tar entry path")?.into_owned();
        reject_unsafe_components(&path)?;
        reject_deep_path(&path)?;

        count += 1;
        if count > MAX_ENTRIES {
            anyhow::bail!("archive has too many entries (max {MAX_ENTRIES})");
        }

        let mode = entry.header().mode().unwrap_or(0);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            reject_unsafe_mode(mode, true, &path)?;
            fs::create_dir_all(dst.join(&path))
                .with_context(|| format!("create dir {}", dst.join(&path).display()))?;
        } else if entry_type.is_file() {
            reject_unsafe_mode(mode, false, &path)?;
            let size = entry.header().size().unwrap_or(0);
            if size > MAX_FILE_BYTES {
                anyhow::bail!(
                    "archive entry exceeds {MAX_FILE_BYTES} bytes: {}",
                    path.display()
                );
            }
            total = total.saturating_add(size);
            if total > MAX_TOTAL_BYTES {
                anyhow::bail!("archive unpacks to more than {MAX_TOTAL_BYTES} bytes");
            }
            let dest = dst.join(&path);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            entry
                .unpack(&dest)
                .with_context(|| format!("unpack {}", dest.display()))?;
            // `unpack` applies archive metadata, so clamp the resulting mode.
            apply_safe_mode(&dest, Some(mode))?;
        } else if entry_type.is_symlink() {
            anyhow::bail!("archive contains symlink: {}", path.display());
        } else if entry_type.is_hard_link() {
            anyhow::bail!("archive contains hardlink: {}", path.display());
        } else {
            anyhow::bail!("archive contains special entry: {}", path.display());
        }
    }

    Ok(())
}

fn reject_deep_path(path: &Path) -> Result<()> {
    if path.components().count() > MAX_DEPTH {
        anyhow::bail!("archive path is too deeply nested: {}", path.display());
    }
    Ok(())
}

fn reject_unsafe_components(path: &Path) -> Result<()> {
    if path.is_absolute() {
        anyhow::bail!("archive contains absolute path: {}", path.display());
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        anyhow::bail!("archive contains path traversal: {}", path.display());
    }
    Ok(())
}

fn reject_unsafe_mode(mode: u32, is_dir: bool, path: &Path) -> Result<()> {
    if mode & 0o6000 != 0 {
        anyhow::bail!("archive entry has setuid/setgid bits: {}", path.display());
    }
    if mode & 0o002 != 0 {
        let kind = if is_dir { "directory" } else { "file" };
        anyhow::bail!("archive contains world-writable {kind}: {}", path.display());
    }
    Ok(())
}

fn apply_safe_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .with_context(|| format!("set mode on {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_gz_bytes(mode: u32) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let data = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn write_temp(bytes: &[u8], suffix: &str) -> tempfile::TempPath {
        let mut tmp = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        tmp.write_all(bytes).unwrap();
        tmp.into_temp_path()
    }

    #[test]
    fn tar_rejects_world_writable_files() {
        let archive = write_temp(&tar_gz_bytes(0o666), ".tar.gz");
        let dst = tempfile::tempdir().unwrap();
        let error = format!("{:#}", extract_tar_gz(&archive, dst.path()).unwrap_err());
        assert!(error.contains("world-writable file"), "{error}");
    }

    #[test]
    fn tar_rejects_setuid_files() {
        let archive = write_temp(&tar_gz_bytes(0o4755), ".tar.gz");
        let dst = tempfile::tempdir().unwrap();
        let error = format!("{:#}", extract_tar_gz(&archive, dst.path()).unwrap_err());
        assert!(error.contains("setuid"), "{error}");
    }

    #[test]
    fn tar_clamps_sticky_bits_after_unpack() {
        // Sticky (0o1000) passes the rejection checks but must be stripped.
        let archive = write_temp(&tar_gz_bytes(0o1755), ".tar.gz");
        let dst = tempfile::tempdir().unwrap();
        extract_tar_gz(&archive, dst.path()).unwrap();
        let mode = fs::metadata(dst.path().join("file.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755, "sticky bit must be stripped");
    }

    #[test]
    fn zip_rejects_world_writable_files() {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            let options: zip::write::SimpleFileOptions =
                zip::write::SimpleFileOptions::default().unix_permissions(0o666);
            writer.start_file("file.txt", options).unwrap();
            writer.write_all(b"hello").unwrap();
            writer.finish().unwrap();
        }
        let archive = write_temp(buffer.get_ref(), ".zip");
        let dst = tempfile::tempdir().unwrap();
        let error = format!("{:#}", extract_zip(&archive, dst.path()).unwrap_err());
        assert!(error.contains("world-writable file"), "{error}");
    }

    #[test]
    fn zip_rejects_path_traversal_entry() {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buffer);
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            writer.start_file("../escape.txt", options).unwrap();
            writer.write_all(b"pwned").unwrap();
            writer.finish().unwrap();
        }
        let archive = write_temp(buffer.get_ref(), ".zip");
        let dst = tempfile::tempdir().unwrap();
        let error = format!("{:#}", extract_zip(&archive, dst.path()).unwrap_err());
        assert!(
            error.contains("unsafe path") || error.contains("traversal"),
            "zip-slip must be rejected: {error}"
        );
        // Rejection must happen before anything is written outside the destination.
        assert!(
            !dst.path().with_file_name("escape.txt").exists(),
            "traversal entry escaped the destination"
        );
    }

    // `tar::Builder` cannot construct traversal entries for a unit test. Tar
    // extraction uses the same component check exercised by the zip test.
}
