use clap::{Args, Parser, Subcommand};
use darkbox::{Limits, Mode, Report, Status};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

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
    writeln!(writer, "Application-profile validation: not performed")
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
    let mut report = darkbox::analyze(&input.file, mode, limits);
    if require_profile && report.status == Status::Passed {
        report.status = Status::Unsupported;
        report.diagnostics.push(darkbox::Diagnostic {
            severity: "error", code: "profile.required".into(), path: None,
            message: "This binary has no application-profile validators; common checks alone do not satisfy --require-profile".into(),
        });
    }
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
            eprintln!("Output error: {error}");
            ExitCode::from(5)
        }
    }
}
