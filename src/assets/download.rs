//! Downloads an asset archive over HTTPS to a temp file, fsyncs it, and
//! verifies its SHA-256 when the manifest provides one.

use crate::assets::ArchiveFormat;
use crate::assets::extract::{extract_tar_gz, extract_tar_xz, extract_zip};
use crate::net::http::{DownloadLimits, UreqTransport, download_https};
use crate::sanitize::terminal;
use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

pub fn download_archive(
    name: &str,
    url: &str,
    format: ArchiveFormat,
    sha256: Option<&str>,
    allow_ssrf: bool,
) -> Result<tempfile::TempPath> {
    let display_name = terminal(name);
    println!("  ↓  {display_name}");

    let mut tmp = tempfile::Builder::new()
        .prefix("malm-asset-")
        .suffix(&format!(".{}", format.extension()))
        .tempfile()
        .context("create temp file")?;

    let limits = DownloadLimits {
        // Block config-supplied URLs from metadata and internal services unless
        // the user explicitly allows private artifact hosts.
        allow_ssrf,
        ..DownloadLimits::default()
    };
    let transport = UreqTransport::new(&limits);
    {
        let mut writer = io::BufWriter::new(tmp.as_file_mut());
        download_https(&transport, url, &limits, &mut writer)
            .with_context(|| format!("download failed for {name}"))?;
        writer.flush().context("flush downloaded data")?;
    }
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("sync downloaded file for {name}"))?;

    if let Some(expected) = sha256 {
        verify_sha256(tmp.path(), expected, name)?;
    }

    Ok(tmp.into_temp_path())
}

pub fn extract_archive(archive: &Path, format: ArchiveFormat, dest_dir: &Path) -> Result<()> {
    match format {
        ArchiveFormat::Zip => extract_zip(archive, dest_dir).context("extract zip")?,
        ArchiveFormat::TarXz => extract_tar_xz(archive, dest_dir).context("extract tar.xz")?,
        ArchiveFormat::TarGz => extract_tar_gz(archive, dest_dir).context("extract tar.gz")?,
    }
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str, name: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!("SHA256 mismatch for {name}: expected {expected}, got {actual}");
    }
    Ok(())
}
