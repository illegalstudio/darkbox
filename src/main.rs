use clap::{Args, Parser, Subcommand};
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
    },
    /// Show archive metadata and SQLite inventories without certifying conformance.
    Inspect(Input),
    /// List the exact specification versions embedded in this binary.
    Versions {
        #[arg(long)]
        json: bool,
    },
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
    #[arg(long, default_value_t = 536_870_912)]
    max_archive_bytes: u64,
    #[arg(long, default_value_t = 268_435_456)]
    max_entry_bytes: u64,
    #[arg(long, default_value_t = 1_073_741_824)]
    max_total_bytes: u64,
    #[arg(long, default_value_t = 10_000)]
    max_entries: usize,
    #[arg(long, default_value_t = 4_194_304)]
    max_metadata_bytes: u64,
    #[arg(long, default_value_t = 60)]
    timeout_seconds: u64,
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
    let (mode, input, require_profile) = match cli.command {
        Command::Verify {
            input,
            require_profile,
        } => (Mode::Verify, input, require_profile),
        Command::Inspect(input) => (Mode::Inspect, input, false),
        Command::Versions { json } => {
            let mut output = io::stdout().lock();
            let versions: Vec<_> = darkbox::supported_versions().map(|(version, released)| serde_json::json!({"version": version, "released": released})).collect();
            if json {
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"cli_version": env!("CARGO_PKG_VERSION"), "versions": versions})
                )?;
            } else {
                for version in versions {
                    writeln!(
                        output,
                        "{} ({})",
                        version["version"].as_str().unwrap(),
                        if version["released"].as_bool().unwrap() {
                            "released"
                        } else {
                            "not yet released"
                        }
                    )?;
                }
            }
            return Ok(0);
        }
    };
    let limits = Limits {
        max_archive_bytes: input.max_archive_bytes,
        max_entry_bytes: input.max_entry_bytes,
        max_total_bytes: input.max_total_bytes,
        max_entries: input.max_entries,
        max_metadata_bytes: input.max_metadata_bytes,
        timeout_seconds: input.timeout_seconds,
    };
    let keys = input.decryption_keys.as_ref().map(load_keys).transpose()?;
    let mut options = darkbox::VerificationOptions {
        require_protection: input.require_protection,
        require_profile,
        ..Default::default()
    };
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
    let report = darkbox::analyze_with(&input.file, mode, limits, &options);
    let mut output = io::stdout().lock();
    if input.json {
        serde_json::to_writer_pretty(&mut output, &report)?;
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
