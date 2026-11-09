//! A bounded inventory shared by ZIP and quiescent directory inputs.
use crate::{Error, Limits, Result, Status, container, paths};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use zip::{CompressionMethod, ZipArchive};

pub(crate) enum Source {
    Zip {
        archive: ZipArchive<File>,
        file: File,
    },
    Directory {
        root: PathBuf,
        entries: Vec<(String, u64)>,
        lock: Arc<crate::live::DirectoryLock>,
        overrides: BTreeMap<String, PathBuf>,
    },
}

pub(crate) struct Entry<'a> {
    pub reader: Box<dyn Read + 'a>,
    pub size: u64,
    pub compressed: u64,
    pub crc: Option<u32>,
    pub compression: &'static str,
}

impl Source {
    pub fn open(
        path: &Path,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<(Self, container::Directory)> {
        let metadata = fs::symlink_metadata(path).map_err(crate::io_failure)?;
        if metadata.is_dir() {
            let lock = crate::live::shared_lock(path)?;
            Self::directory_locked(
                path,
                lock,
                BTreeMap::new(),
                &BTreeSet::new(),
                limits,
                deadline,
            )
        } else if metadata.is_file() {
            Self::zip(
                File::open(path).map_err(crate::io_failure)?,
                limits,
                deadline,
            )
        } else {
            Err(Error::new(
                Status::OperationalError,
                "io.file_type",
                "Input must be a regular file or directory, without symbolic links",
            ))
        }
    }
    pub(crate) fn directory_locked(
        path: &Path,
        lock: Arc<crate::live::DirectoryLock>,
        overrides: BTreeMap<String, PathBuf>,
        omitted: &BTreeSet<String>,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<(Self, container::Directory)> {
        let mut entries = Vec::new();
        let mut nodes = paths::Nodes::new();
        if let Some(staging) = &limits.staging_directory
            && fs::canonicalize(staging)
                .map_err(crate::io_failure)?
                .starts_with(fs::canonicalize(path).map_err(crate::io_failure)?)
        {
            return Err(Error::invalid(
                "directory.staging",
                "Staging storage must be outside the input package",
            ));
        }
        let mut budget = WalkBudget {
            total: 0,
            remaining: limits.max_entries,
        };
        walk(
            path,
            path,
            limits,
            deadline,
            &mut entries,
            &mut nodes,
            &mut budget,
        )?;
        entries.retain(|(name, _)| !omitted.contains(name));
        for (name, replacement) in &overrides {
            let size = fs::metadata(replacement).map_err(crate::io_failure)?.len();
            if let Some(entry) = entries.iter_mut().find(|(n, _)| n == name) {
                entry.1 = size;
            } else {
                entries.push((name.clone(), size));
            }
        }
        if entries.len() > limits.max_entries {
            return Err(Error::limit("Directory overlay exceeds entry limit"));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut nodes = paths::Nodes::new();
        for (name, _) in &entries {
            paths::insert(&mut nodes, name.trim_end_matches('/'), name.ends_with('/'))?;
        }
        let names = entries.iter().map(|(name, _)| name.clone()).collect();
        Ok((
            Self::Directory {
                root: path.into(),
                entries,
                lock,
                overrides,
            },
            container::Directory { names, nodes },
        ))
    }
    pub(crate) fn fork(
        &self,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<(Self, container::Directory)> {
        match self {
            Self::Zip { file, .. } => Self::zip(
                file.try_clone().map_err(crate::io_failure)?,
                limits,
                deadline,
            ),
            Self::Directory {
                root,
                entries,
                lock,
                overrides,
            } => {
                let mut nodes = paths::Nodes::new();
                for (name, _) in entries {
                    paths::insert(&mut nodes, name.trim_end_matches('/'), name.ends_with('/'))?;
                }
                Ok((
                    Self::Directory {
                        root: root.clone(),
                        entries: entries.clone(),
                        lock: lock.clone(),
                        overrides: overrides.clone(),
                    },
                    container::Directory {
                        names: entries.iter().map(|(n, _)| n.clone()).collect(),
                        nodes,
                    },
                ))
            }
        }
    }
    pub fn zip(
        mut file: File,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<(Self, container::Directory)> {
        let length = file.metadata().map_err(crate::io_failure)?.len();
        if length > limits.max_archive_bytes {
            return Err(Error::limit(
                "Compressed archive exceeds --max-archive-bytes",
            ));
        }
        let directory = container::preflight(&mut file, length, limits, deadline)?;
        let reference = file.try_clone().map_err(crate::io_failure)?;
        let archive = ZipArchive::new(file).map_err(crate::zip_failure)?;
        if archive.len() != directory.names.len() {
            return Err(Error::invalid(
                "zip.directory",
                "ZIP entry inventories disagree",
            ));
        }
        Ok((
            Self::Zip {
                archive,
                file: reference,
            },
            directory,
        ))
    }
    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }
    pub fn entry(&mut self, index: usize, name: &str) -> Result<Entry<'_>> {
        match self {
            Self::Zip { archive, .. } => {
                let file = archive.by_index(index).map_err(crate::zip_failure)?;
                if file.name_raw() != name.as_bytes() {
                    return Err(Error::invalid("zip.directory", "ZIP entry names disagree"));
                }
                let directory = name.ends_with('/');
                if file.is_symlink()
                    || file.unix_mode().is_some_and(|mode| {
                        let kind = mode & 0o170000;
                        kind != 0 && kind != if directory { 0o040000 } else { 0o100000 }
                    })
                {
                    return Err(Error::invalid(
                        "zip.entry_type",
                        "Only regular files and directories are allowed",
                    )
                    .at(name));
                }
                if directory && file.size() != 0 {
                    return Err(Error::invalid(
                        "zip.directory_data",
                        "Directory entries cannot contain data",
                    )
                    .at(name));
                }
                let entry = Entry {
                    size: file.size(),
                    compressed: file.compressed_size(),
                    crc: Some(file.crc32()),
                    compression: match file.compression() {
                        CompressionMethod::Stored => "store",
                        CompressionMethod::Deflated => "deflate",
                        _ => {
                            return Err(Error::invalid(
                                "zip.compression",
                                "Unsupported compression",
                            ));
                        }
                    },
                    reader: Box::new(file),
                };
                Ok(entry)
            }
            Self::Directory {
                root,
                entries,
                overrides,
                ..
            } => {
                let (entry_name, size) = &entries[index];
                debug_assert_eq!(name, entry_name);
                let path = overrides
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| root.join(name.trim_end_matches('/')));
                let metadata = fs::symlink_metadata(&path).map_err(crate::io_failure)?;
                if name.ends_with('/') && metadata.is_dir() {
                    return Ok(Entry {
                        reader: Box::new(io::empty()),
                        size: 0,
                        compressed: 0,
                        crc: None,
                        compression: "none",
                    });
                }
                if !metadata.is_file() || metadata.len() != *size {
                    return Err(Error::invalid(
                        "directory.changed",
                        "Directory entry changed during analysis",
                    )
                    .at(name));
                }
                Ok(Entry {
                    reader: Box::new(File::open(path).map_err(crate::io_failure)?),
                    size: *size,
                    compressed: *size,
                    crc: None,
                    compression: "none",
                })
            }
        }
    }
}

struct WalkBudget {
    total: u64,
    remaining: usize,
}

fn walk(
    root: &Path,
    directory: &Path,
    limits: &Limits,
    deadline: Instant,
    entries: &mut Vec<(String, u64)>,
    nodes: &mut paths::Nodes,
    budget: &mut WalkBudget,
) -> Result<()> {
    // Bound before collecting or sorting attacker-controlled directory contents.
    let mut children = Vec::new();
    for item in fs::read_dir(directory).map_err(crate::io_failure)? {
        container::check_deadline(deadline)?;
        if budget.remaining == 0 {
            return Err(Error::limit("Directory entry count exceeds --max-entries"));
        }
        budget.remaining -= 1;
        children.push(item.map_err(crate::io_failure)?);
    }
    children.sort_by_key(|entry| entry.file_name());
    for item in children {
        container::check_deadline(deadline)?;
        if entries.len() >= limits.max_entries {
            return Err(Error::limit("Directory entry count exceeds --max-entries"));
        }
        let path = item.path();
        let name = path
            .strip_prefix(root)
            .unwrap()
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .ok_or_else(|| Error::invalid("path.encoding", "Paths must use ASCII"))
            })
            .collect::<Result<Vec<_>>>()?
            .join("/");
        let kind = item.file_type().map_err(crate::io_failure)?;
        if !kind.is_file() && !kind.is_dir() {
            return Err(Error::invalid(
                "directory.entry_type",
                "Symbolic links and special entries are forbidden",
            )
            .at(name));
        }
        paths::insert(nodes, &name, kind.is_dir())?;
        if kind.is_dir() {
            entries.push((format!("{name}/"), 0));
            walk(root, &path, limits, deadline, entries, nodes, budget)?;
        } else {
            let size = item.metadata().map_err(crate::io_failure)?.len();
            if size > limits.max_entry_bytes {
                return Err(Error::limit("Directory file exceeds --max-entry-bytes").at(name));
            }
            budget.total = budget
                .total
                .checked_add(size)
                .filter(|sum| *sum <= limits.max_total_bytes)
                .ok_or_else(|| Error::limit("Directory size exceeds --max-total-bytes"))?;
            entries.push((name, size));
        }
    }
    Ok(())
}
