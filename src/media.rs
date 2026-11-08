//! Direct bounded byte access to verified STORE resources.
use crate::{Error, Limits, Mode, Report, Status, VerificationOptions};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};
use zip::{CompressionMethod, ZipArchive, write::SimpleFileOptions};

pub(crate) fn file_options(path: &str) -> SimpleFileOptions {
    let suffix = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if matches!(
        suffix.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "avif"
            | "gif"
            | "mp4"
            | "mov"
            | "m4v"
            | "webm"
            | "mkv"
            | "mp3"
            | "aac"
            | "ogg"
            | "flac"
            | "zip"
            | "gz"
            | "zst"
    ) {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .with_alignment(4096)
            .large_file(true)
    } else {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .large_file(true)
    }
}

/// Owns an archive file descriptor and exposes one raw STORE entry as Read + Seek.
/// The caller must exclude concurrent writes for the lifetime of this handle.
/// Protected entries return ciphertext, never implicit plaintext.
pub struct StoredResource {
    file: File,
    offset: u64,
    length: u64,
    position: u64,
    report: Report,
}
impl StoredResource {
    /// Fully verify the archive through the same open descriptor, without copying
    /// or extracting ordinary media. Databases/callback resources may need staging.
    pub fn open(
        path: impl AsRef<Path>,
        resource: &str,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Self, Error> {
        let path = path.as_ref();
        if !fs::symlink_metadata(path)
            .map_err(crate::io_failure)?
            .is_file()
        {
            return Err(Error::invalid(
                "media.file_type",
                "Direct access requires a regular ZIP file",
            ));
        }
        let file = File::open(path).map_err(crate::io_failure)?;
        let (report, _) = crate::analyze_input(
            path,
            Mode::Verify,
            limits,
            options,
            false,
            Some(file.try_clone().map_err(crate::io_failure)?),
        );
        if report.status != Status::Passed {
            return Err(Error::new(
                report.status,
                "media.validation",
                "Archive verification failed",
            )
            .with_report(report));
        }
        let mut archive = ZipArchive::new(file.try_clone().map_err(crate::io_failure)?)
            .map_err(crate::zip_failure)?;
        let entry = archive.by_name(resource).map_err(crate::zip_failure)?;
        if entry.is_dir() || entry.compression() != CompressionMethod::Stored {
            return Err(Error::new(
                Status::Unsupported,
                "media.compression",
                "Direct byte access requires a regular STORE entry",
            )
            .at(resource));
        }
        Ok(Self {
            file,
            offset: entry.data_start(),
            length: entry.size(),
            position: 0,
            report,
        })
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn data_offset(&self) -> u64 {
        self.offset
    }
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}
impl Read for StoredResource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let count = remaining.min(buffer.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        self.file
            .seek(SeekFrom::Start(self.offset + self.position))?;
        let read = self.file.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.position += read as u64;
        Ok(read)
    }
}
impl Seek for StoredResource {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::Current(p) => self.position as i128 + p as i128,
            SeekFrom::End(p) => self.length as i128 + p as i128,
        };
        self.position =
            u64::try_from(target).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}
