use clap::{Args, Parser, Subcommand, ValueEnum};
use darkbox::{Limits, Mode, Report};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Inspect and verify Darkbox project archives offline")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check common container rules, canonical documentation and SQLite snapshots.
    Verify {
        #[command(flatten)]
        input: Input,
        /// Fail unless application-profile semantics can also be validated.
        #[arg(long)]
        require_profile: bool,
        /// Verify a delta against its exact complete base edition.
        #[arg(long)]
        base: Option<PathBuf>,
    },
    /// Show archive metadata and SQLite inventories without certifying conformance.
    Inspect {
        #[command(flatten)]
        input: Input,
        /// Inspect unsigned inventory claims without verifying payload bytes.
        #[arg(long)]
        inventory_only: bool,
    },
    /// Pack a quiescent directory into a new ZIP package.
    Pack {
        #[command(flatten)]
        input: Input,
        destination: PathBuf,
    },
    /// Unpack a ZIP into a new quiescent directory package.
    Unpack {
        #[command(flatten)]
        input: Input,
        destination: PathBuf,
    },
    /// Create an incremental transfer between complete base and target editions.
    Delta {
        #[command(flatten)]
        input: Input,
        target: PathBuf,
        destination: PathBuf,
    },
    /// Reconstruct and verify a complete new edition from a base and one delta.
    Merge {
        #[command(flatten)]
        input: Input,
        delta: PathBuf,
        destination: PathBuf,
    },
    /// List the exact specification versions embedded in this binary.
    Versions {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum LimitPreset {
    #[default]
    Default,
    Large,
}
enum Action {
    Analyze,
    VerifyDelta(PathBuf),
    Pack(PathBuf),
    Unpack(PathBuf),
    Delta(PathBuf, PathBuf),
    Merge(PathBuf, PathBuf),
}

#[derive(Args)]
struct Input {
    file: PathBuf,
    /// Emit a structured JSON report.
    #[arg(long)]
    json: bool,
    /// JSON mapping of trusted signer identifiers to hex-encoded public keys.
    #[arg(long)]
    trust_store: Option<PathBuf>,
    /// Private JSON mapping of key identifiers to hex-encoded AES-256 keys.
    #[arg(long)]
    decryption_keys: Option<PathBuf>,
    /// Require the official protection extension by external application policy.
    #[arg(long)]
    require_protection: bool,
    #[arg(long)]
    max_archive_bytes: Option<u64>,
    #[arg(long)]
    max_entry_bytes: Option<u64>,
    #[arg(long)]
    max_total_bytes: Option<u64>,
    #[arg(long)]
    max_entries: Option<usize>,
    #[arg(long)]
    max_metadata_bytes: Option<u64>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    /// Reader-owned bounded policy; individual flags override the preset.
    #[arg(long, value_enum, default_value = "default")]
    limits: LimitPreset,
    /// Private staging on suitable storage, independent of process TMPDIR.
    #[arg(long)]
    staging_directory: Option<PathBuf>,
}

/// The library report with this tool's own version added.
#[derive(serde::Serialize)]
struct CliReport<'a> {
    cli_version: &'static str,
    #[serde(flatten)]
    report: &'a Report,
}

struct KeyStore(BTreeMap<String, Zeroizing<[u8; 32]>>);

impl darkbox::protection::DecryptionKeys for KeyStore {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.0.get(id).map(|key| Zeroizing::new(**key))
    }
}

fn load_keys(path: &PathBuf) -> io::Result<KeyStore> {
    use std::io::Read;
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key store must be a regular file",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(4_194_305)
        .read_to_end(&mut bytes)?;
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Key store must be a JSON object of identifiers and 64 hexadecimal characters per key",
        )
    };
    if bytes.len() > 4_194_304 {
        return Err(invalid());
    }
    let values: BTreeMap<String, Zeroizing<String>> =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let mut keys = BTreeMap::new();
    for (id, text) in values {
        if text.len() != 64 {
            return Err(invalid());
        }
        let mut key = Zeroizing::new([0u8; 32]);
        for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = (pair[0] as char).to_digit(16).ok_or_else(invalid)?;
            let low = (pair[1] as char).to_digit(16).ok_or_else(invalid)?;
            key[index] = ((high << 4) | low) as u8;
        }
        keys.insert(id, key);
    }
    Ok(KeyStore(keys))
}

fn text_report(report: &Report, writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "File: {}", report.file.escape_debug())?;
    writeln!(writer, "Status: {:?} ({})", report.status, report.scope)?;
    if let Some(manifest) = &report.manifest {
        if let Some(version) = manifest
            .pointer("/darkbox/version")
            .and_then(|v| v.as_str())
        {
            writeln!(writer, "Darkbox: {}", version.escape_debug())?;
        }
        if let Some(application) = manifest.get("application") {
            writeln!(writer, "Application: {application}")?;
        }
        if let Some(creator) = manifest.get("creator") {
            writeln!(writer, "Creator: {creator}")?;
        }
    }
    writeln!(writer, "Entries: {}", report.entries.len())?;
    if report.command == Mode::Inspect {
        for entry in &report.entries {
            writeln!(
                writer,
                "  {} {} ({} bytes)",
                entry.kind,
                entry.path.escape_debug(),
                entry.bytes
            )?;
        }
    }
    for db in &report.databases {
        writeln!(
            writer,
            "Database: {} (user_version {}, journal {})",
            db.path.escape_debug(),
            db.user_version,
            db.journal_mode.escape_debug()
        )?;
        for table in &db.tables {
            writeln!(writer, "  table {}", table.escape_debug())?;
        }
    }
    for diagnostic in &report.diagnostics {
        let path = diagnostic.path.as_deref().unwrap_or("");
        writeln!(
            writer,
            "{} [{}] {}: {}",
            diagnostic.severity,
            diagnostic.code,
            path.escape_debug(),
            diagnostic.message.escape_debug()
        )?;
    }
    if let Some(protection) = &report.protection {
        writeln!(
            writer,
            "Protection {}: signature {}, inventory {}",
            protection.extension_version.escape_debug(),
            protection.signature,
            if protection.inventory_verified {
                "verified"
            } else {
                "not verified"
            }
        )?;
        for block in &protection.encrypted {
            let context = serde_json::to_string(&block.context)?;
            writeln!(
                writer,
                "  Encrypted {}: authentication {}, plaintext semantics not checked",
                context, block.authentication
            )?;
        }
    }
    writeln!(
        writer,
        "Application-profile validation: {}",
        report.application_validation
    )
}

fn run() -> io::Result<u8> {
    let cli = Cli::parse();
    let (mode, input, require_profile, action) = match cli.command {
        Command::Verify {
            input,
            require_profile,
            base,
        } => (
            Mode::Verify,
            input,
            require_profile,
            base.map(Action::VerifyDelta).unwrap_or(Action::Analyze),
        ),
        Command::Inspect {
            input,
            inventory_only,
        } => (
            if inventory_only {
                Mode::Inventory
            } else {
                Mode::Inspect
            },
            input,
            false,
            Action::Analyze,
        ),
        Command::Pack { input, destination } => {
            (Mode::Verify, input, false, Action::Pack(destination))
        }
        Command::Unpack { input, destination } => {
            (Mode::Verify, input, false, Action::Unpack(destination))
        }
        Command::Delta {
            input,
            target,
            destination,
        } => (
            Mode::Verify,
            input,
            false,
            Action::Delta(target, destination),
        ),
        Command::Merge {
            input,
            delta,
            destination,
        } => (
            Mode::Verify,
            input,
            false,
            Action::Merge(delta, destination),
        ),
        Command::Versions { json } => {
            let mut output = io::stdout().lock();
            let state = |released: bool| {
                if released {
                    "released"
                } else {
                    "not yet released"
                }
            };
            if json {
                let versions: Vec<_> = darkbox::supported_versions()
                    .map(|v| serde_json::json!({"version": v.version, "released": v.released}))
                    .collect();
                let extensions: Vec<_> = darkbox::supported_extensions()
                    .map(|e| serde_json::json!({"namespace": e.namespace, "version": e.version, "released": e.released, "minimum_common": e.minimum_common}))
                    .collect();
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"cli_version": env!("CARGO_PKG_VERSION"), "versions": versions, "extensions": extensions})
                )?;
            } else {
                for version in darkbox::supported_versions() {
                    writeln!(output, "{} ({})", version.version, state(version.released))?;
                }
                for extension in darkbox::supported_extensions() {
                    writeln!(
                        output,
                        "extension {} {} for common {} and later ({})",
                        extension.namespace,
                        extension.version,
                        extension.minimum_common,
                        state(extension.released)
                    )?;
                }
            }
            return Ok(0);
        }
    };
    let mut limits = match input.limits {
        LimitPreset::Default => Limits::default(),
        LimitPreset::Large => Limits::large(),
    };
    if let Some(value) = input.max_archive_bytes {
        limits.max_archive_bytes = value;
    }
    if let Some(value) = input.max_entry_bytes {
        limits.max_entry_bytes = value;
    }
    if let Some(value) = input.max_total_bytes {
        limits.max_total_bytes = value;
    }
    if let Some(value) = input.max_entries {
        limits.max_entries = value;
    }
    if let Some(value) = input.max_metadata_bytes {
        limits.max_metadata_bytes = value;
    }
    if let Some(value) = input.timeout_seconds {
        limits.timeout_seconds = value;
    }
    limits.staging_directory = input.staging_directory.clone();
    let keys = input.decryption_keys.as_ref().map(load_keys).transpose()?;
    let mut options = darkbox::VerificationOptions::default();
    options.require_protection = input.require_protection;
    options.require_profile = require_profile;
    options.decryption_keys = keys
        .as_ref()
        .map(|keys| keys as &dyn darkbox::protection::DecryptionKeys);
    if let Some(path) = &input.trust_store {
        options.trusted_signers = load_keys(path)?
            .0
            .into_iter()
            .map(|(id, key)| (id, *key))
            .collect();
    }
    let result = match action {
        Action::Analyze => Ok(darkbox::analyze_with(
            &input.file,
            mode,
            limits.clone(),
            &options,
        )),
        Action::VerifyDelta(base) => {
            darkbox::verify_delta(base, &input.file, limits.clone(), &options)
        }
        Action::Pack(destination) => {
            darkbox::pack(&input.file, destination, limits.clone(), &options)
        }
        Action::Unpack(destination) => {
            darkbox::unpack(&input.file, destination, limits.clone(), &options)
        }
        Action::Delta(target, destination) => {
            darkbox::create_delta(&input.file, target, destination, limits.clone(), &options)
        }
        Action::Merge(delta, destination) => {
            darkbox::merge(&input.file, delta, destination, limits.clone(), &options)
        }
    };
    let mut report = result.unwrap_or_else(|error| {
        Report::from_failure(mode, input.file.display().to_string(), limits, error)
    });
    // The library reports limits neutrally; this tool names its own options.
    for diagnostic in &mut report.diagnostics {
        if diagnostic.code == "limits.exceeded" {
            diagnostic.message.push_str("; select --limits large or raise --max-archive-bytes, --max-entry-bytes, --max-total-bytes, --max-entries, --max-metadata-bytes or --timeout-seconds as appropriate");
        }
    }
    let mut output = io::stdout().lock();
    if input.json {
        serde_json::to_writer_pretty(
            &mut output,
            &CliReport {
                cli_version: env!("CARGO_PKG_VERSION"),
                report: &report,
            },
        )?;
        writeln!(output)?;
    } else {
        text_report(&report, &mut output)?;
    }
    Ok(report.status.exit_code())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("Command error: {error}");
            ExitCode::from(if error.kind() == io::ErrorKind::InvalidInput {
                2
            } else {
                5
            })
        }
    }
}
